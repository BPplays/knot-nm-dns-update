use anyhow::{Context, Result};
use std::{result::Result::Ok, sync::Arc};
use resolv_conf::Config as rConfig;
use serde_json::Value;
use std::{
	collections::HashSet, fs::{self, OpenOptions}, io::Write, net::IpAddr, path::{Path, PathBuf}, process::{Command, Stdio}, thread::{self, current}, time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use http_body_util::{Empty, Full};
use hyper::{body::Bytes, Request};
use hyper_util::{
	client::legacy::Client,
};
use hyperlocal::{UnixClientExt, Uri};

use sha3::{Digest, Sha3_256, Sha3_512};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

use clap::Parser;


#[derive(Debug, Clone, PartialEq, Eq, Default)]
enum CacheClear {
	#[default]
	None,
	All,
	Specific(Vec<String>),
}

impl std::str::FromStr for CacheClear {
	type Err = std::convert::Infallible;

	fn from_str(value: &str) -> Result<Self, Self::Err> {
		match value.to_lowercase().as_str() {
			_ if value.is_empty() => {
				return Ok(Self::All);
			}
			"all" => {
				return Ok(Self::All)
			}
			"none" => {
				return Ok(Self::None)
			}
			_ => {}
		}

		let domains = value
			.split(',')
			.map(normalize_domain)
			.collect();

		Ok(Self::Specific(domains))
	}
}


#[derive(Debug, Clone)]
struct Config<'a> {
	resolv_conf: &'a Path,
	run_dir: &'a Path,
	resolv_anti_rfc6761: &'a Path,

	knot_resolver_last_started: &'a Path,

	resolv_nm_conf: &'a Path,
}

#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
	/// unix socket path for knot-resolver kres-api.
	#[arg(long = "kres-api-sock", default_value = "/run/knot-resolver/kres-api.sock")]
	kres_api_sock: PathBuf,

	/// Copy NetworkManager's search domains into /etc/resolv.conf.
	#[arg(long = "copy-search")]
	copy_search: bool,

	/// Use heuristic optimizations like only running when relevant files have changed
	#[arg(long, default_value_t = false)]
	fast_path: bool,

	/// Clear Knot Resolver's cache when upstream nameservers change.
	///
	/// No value clears the entire cache; a domain clears that subtree.
	#[arg(
		long = "clear-cache",
		value_name = "DOMAIN[,DOMAIN...]",
		num_args = 0..=1,
		default_missing_value = "",
		default_value = "",
	)]
	clear_cache: CacheClear,
}


const RESOLV_RETRY_TIMEOUT: Duration = Duration::from_secs(30);
const RESOLV_RETRY_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, PartialEq, Eq)]
struct ForwardRule {
	subtree: Vec<String>,
	servers: Vec<IpAddr>,
	dnssec: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvData {
	nameservers: Vec<IpAddr>,
	search_domains: Vec<String>,
	bytes: Vec<u8>,
}

fn read_resolv_conf(
	path: impl AsRef<Path>,
) -> Result<ResolvData> {
	let path = path.as_ref();
	let deadline = Instant::now() + RESOLV_RETRY_TIMEOUT;

	let mut last_error;

	loop {
		match read_resolv_conf_once(path) {
			Ok(data) => {
				if !data.nameservers.is_empty() {
					log::info!(
						"using {} nameserver(s) from {}: {:?}",
						data.nameservers.len(),
						path.display(),
						data.nameservers
					);

					return Ok(data);
				}

				last_error = Some(anyhow::anyhow!(
					"{} contains no usable nameservers",
					path.display()
				));
			}

			Err(err) => {
				last_error = Some(err);
			}
		}

		let now = Instant::now();

		if now >= deadline {
			return Err(last_error.unwrap_or_else(|| {
				anyhow::anyhow!(
					"timed out after {}s waiting for usable nameservers in {}",
					RESOLV_RETRY_TIMEOUT.as_secs(),
					path.display()
				)
			}));
		}

		let remaining = deadline - now;
		thread::sleep(RESOLV_RETRY_INTERVAL.min(remaining));
	}
}

fn read_resolv_conf_once(
	path: &Path,
) -> Result<ResolvData> {
	let data = fs::read(path)
		.with_context(|| format!("failed to read {}", path.display()))?;

	let config = rConfig::parse(&data)
		.with_context(|| format!("failed to parse {}", path.display()))?;

	// Preserve the order in resolv.conf while removing duplicate
	// nameservers after their first occurrence.
	let mut seen = HashSet::new();

	let nameservers = config
		.nameservers.clone()
		.into_iter()
		.filter(|addr| match addr {
			resolv_conf::ScopedIp::V6(_, scope) => scope.is_none(),
			resolv_conf::ScopedIp::V4(_) => true,
		})
		.map(Into::into)
		.filter(|addr: &IpAddr| seen.insert(*addr))
		.collect();

	let search_domains = config
		.get_search()
		.cloned()
		.unwrap_or_default();

	Ok(ResolvData {
		nameservers,
		search_domains,
		bytes: data,
	})
}

fn atomic_write(path: impl AsRef<Path>, data: impl AsRef<[u8]>) -> Result<()> {
	let path = path.as_ref();

	let parent = path.parent().context("atomic write target has no parent")?;

	fs::create_dir_all(parent)
		.with_context(|| format!("failed to create {}", parent.display()))?;

	let file_name = path
		.file_name()
		.context("atomic write target has no file name")?
		.to_string_lossy();

	let pid = std::process::id();

	let timestamp = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap_or_default()
		.as_nanos();

	let tmp_path = parent.join(format!(
		".{file_name}.tmp-{pid}-{timestamp}"
	));

	let result = (|| -> Result<()> {
		let mut file = OpenOptions::new()
			.write(true)
			.create_new(true)
			.open(&tmp_path)
			.with_context(|| {
				format!(
					"failed to create temporary file {}",
					tmp_path.display()
				)
			})?;

		file.write_all(data.as_ref())
			.with_context(|| {
				format!(
					"failed to write temporary file {}",
					tmp_path.display()
				)
			})?;

		file.sync_all()
			.with_context(|| {
				format!(
					"failed to sync temporary file {}",
					tmp_path.display()
				)
			})?;

		fs::rename(&tmp_path, path)
			.with_context(|| {
				format!(
					"failed to atomically replace {}",
					path.display()
				)
			})?;

		Ok(())
	})();

	// If anything failed before rename, remove the temporary file.
	if result.is_err() {
		let _ = fs::remove_file(&tmp_path);
	}

	result
}

fn read_anti_rfc6761(path: impl AsRef<Path>) -> Result<Vec<String>> {
	let path = path.as_ref();

	let data = fs::read_to_string(path)
		.with_context(|| format!("failed to read {}", path.display()))?;

	let mut domains = Vec::new();

	for line in data.lines() {
		let line = line.trim();

		if line.is_empty() || line.starts_with('#') {
			continue;
		}

		let domain = line
			.split_once('#')
			.map_or(line, |(domain, _)| domain)
			.trim();

		if domain.is_empty() {
			continue;
		}

		let domain = normalize_domain(domain);

		domains.push(domain);
	}

	domains.sort_unstable();
	domains.dedup();

	Ok(domains)
}

fn normalize_domain(domain: &str) -> String {
	let domain = domain.trim();

	if domain == "." {
		return ".".to_string();
	}

	let domain = domain.trim_end_matches('.');

	if domain.is_empty() {
		".".to_string()
	} else {
		format!("{}.", domain.to_ascii_lowercase())
	}
}

fn build_forward_config(
	servers: &[IpAddr],
	anti_rfc6761: &[String],
) -> Value {
	let mut forwards = vec![
		serde_json::json!({
			"subtree": ".",
			"servers": servers,
		}),
	];

	if !anti_rfc6761.is_empty() {
		forwards.push(serde_json::json!({
			"subtree": anti_rfc6761,
			"servers": servers,
			"options": {
				"dnssec": false,
			},
		}));
	}

	Value::Array(forwards)
}

async fn get_knot_forward(sock: impl AsRef<Path>) -> Result<Value> {
	let client = Client::unix();

	let uri: hyper::Uri = Uri::new(
		sock,
		"/v1/config/forward",
	).into();

	let request = Request::get(uri)
		.body(Empty::<Bytes>::new())?;

	let response = client.request(request).await?;

	let status = response.status();

	if !status.is_success() {
		let body = http_body_util::BodyExt::collect(response)
			.await?
			.to_bytes();

		anyhow::bail!(
			"Knot Resolver API returned {}: {}",
			status,
			String::from_utf8_lossy(&body),
		);
	}

	let body = http_body_util::BodyExt::collect(response)
		.await?
		.to_bytes();



	if body.iter().all(u8::is_ascii_whitespace) {
		return Ok(Value::Array(Vec::new()));
	}

	serde_json::from_slice(&body)
		.context("invalid JSON from kresctl")
}

async fn set_knot_forward(config: &Value, sock: impl AsRef<Path>) -> Result<()> {
	let json = serde_json::to_vec(config)
		.context("failed to serialize Knot forward configuration")?;

	let client = Client::unix();

	let uri: hyper::Uri = Uri::new(
		sock,
		"/v1/config/forward",
	).into();

	let request = Request::put(uri)
		.header("Content-Type", "application/json")
		.body(Full::new(Bytes::from(json)))?;

	let response = client.request(request).await?;

	let status = response.status();

	let body = http_body_util::BodyExt::collect(response)
		.await?
		.to_bytes();

	if !status.is_success() {
		anyhow::bail!(
			"Knot Resolver API returned {}: {}",
			status,
			String::from_utf8_lossy(&body).trim()
		);
	}


	Ok(())
}

fn canonicalize_forward(value: &Value) -> Result<Vec<ForwardRule>> {
	let rules = value
		.as_array()
		.context("Knot /forward is not an array")?;

	let mut result = Vec::with_capacity(rules.len());

	for (index, rule) in rules.iter().enumerate() {
		let object = rule
			.as_object()
			.with_context(|| {
				format!("Knot /forward rule {index} is not an object")
			})?;

		let subtree = match object.get("subtree") {
			Some(Value::String(value)) => {
				vec![normalize_domain(value)]
			}

			Some(Value::Array(values)) => values
				.iter()
				.enumerate()
				.map(|(subtree_index, value)| {
					let value = value.as_str().with_context(|| {
						format!(
							"Knot /forward rule {index} subtree[{subtree_index}] \
							 is not a string"
						)
					})?;

					Ok(normalize_domain(value))
				})
				.collect::<Result<Vec<_>>>()?,

			Some(other) => {
				anyhow::bail!(
					"Knot /forward rule {index} has invalid subtree: {other}"
				);
			}

			None => Vec::new(),
		};

		let servers = object
			.get("servers")
			.and_then(Value::as_array)
			.with_context(|| {
				format!(
					"Knot /forward rule {index} is missing servers array"
				)
			})?
			.iter()
			.enumerate()
			.map(|(server_index, value)| {
				let value = value.as_str().with_context(|| {
					format!(
						"Knot /forward rule {index} server[{server_index}] \
						 is not a string"
					)
				})?;

				value.parse::<IpAddr>().with_context(|| {
					format!(
						"invalid IP address in Knot /forward rule {index}: \
						 {value:?}"
					)
				})
			})
			.collect::<Result<Vec<_>>>()?;

		let dnssec = object
			.get("options")
			.and_then(Value::as_object)
			.and_then(|options| options.get("dnssec"))
			.and_then(Value::as_bool);

		result.push(ForwardRule {
			subtree,
			servers,
			dnssec,
		});
	}

	Ok(result)
}


fn update_search_domains(
	path: impl AsRef<Path>,
	search_domains: &[String],
) -> Result<()> {
	let path = path.as_ref();

	let current = read_resolv_conf_once(path)?;

	// Nothing to change.
	if current.search_domains == search_domains {
		log::debug!(
			"{} search domains are already up to date: {:?}",
			path.display(),
			search_domains
		);

		return Ok(());
	}

	let text = String::from_utf8(current.bytes)
		.with_context(|| format!("{} is not valid UTF-8", path.display()))?;

	let replacement = if search_domains.is_empty() {
		None
	} else {
		Some(format!("search {}", search_domains.join(" ")))
	};

	let mut output = String::with_capacity(text.len() + 256);
	let mut replaced = false;

	for line in text.split_inclusive('\n') {
		let line_without_newline = line.strip_suffix('\n').unwrap_or(line);
		let content = line_without_newline.strip_suffix('\r').unwrap_or(line_without_newline);

		let trimmed = content.trim_start();

		let is_search = trimmed
			.split_ascii_whitespace()
			.next()
			== Some("search");

		if trimmed == "search" ||
		   trimmed.starts_with("search ") ||
		   trimmed.starts_with("search	") ||
		   is_search {
			replaced = true;

			if let Some(replacement) = &replacement {
				output.push_str(replacement);

				// Preserve CRLF if the original line used it.
				if line_without_newline.ends_with('\r') {
					output.push('\r');
				}

				if line.ends_with('\n') {
					output.push('\n');
				}
			}

			continue;
		}

		output.push_str(line);
	}

	// No existing search directive: add one only when needed.
	if !replaced {
		if let Some(replacement) = &replacement {
			if !output.is_empty() && !output.ends_with('\n') {
				output.push('\n');
			}

			output.push_str(replacement);
			output.push('\n');
		}
	}

	if output.as_bytes() == text.as_bytes() {
		log::debug!(
			"{} search-domain update produced no changes",
			path.display()
		);

		return Ok(());
	}

	atomic_write(path, output.as_bytes())?;

	log::info!(
		"updated search domains in {}: {:?}",
		path.display(),
		search_domains
	);

	Ok(())
}

fn default_hash(b: impl AsRef<[u8]>) -> impl AsRef<[u8]> {
	let mut hasher = Sha3_512::new();
	hasher.update(b);

	let hash = hasher.finalize();
	return hash;
}

fn default_hash_base64(b: impl AsRef<[u8]>) -> String {
	let hash = default_hash(b);
	let encoded = URL_SAFE_NO_PAD.encode(hash);
	return encoded
}

fn get_known_path(path: impl AsRef<Path>, cfg: &Config) -> PathBuf {
	let path = path.as_ref();
	let mut hasher = Sha3_256::new();
	hasher.update(path.as_os_str().as_encoded_bytes());

	let hash = hasher.finalize();
	let encoded = URL_SAFE_NO_PAD.encode(hash);
	let known_path = cfg.run_dir.join("known").join(encoded);
	return known_path
}

#[inline(always)]
fn write_known(
	path: impl AsRef<Path>,
	data: &[u8],
	cfg: &Config,
) -> Result<()> {
	return atomic_write(
		get_known_path(path.as_ref(), cfg),
		known_hash(&data),
	)
}

#[inline(always)]
fn known_hash(b: impl AsRef<[u8]>) -> impl AsRef<[u8]> {
	return default_hash(b);
}

fn matches_known(
	input_path: impl AsRef<Path> + std::fmt::Debug,
	input_data: Option<impl AsRef<[u8]>>,
	cfg: &Config,
) -> bool {
	let path = input_path.as_ref();

	let input_data: Result<Vec<u8>, anyhow::Error> = match input_data {
		Some(data) => Ok(data.as_ref().to_vec()),
		None => fs::read(path).map_err(anyhow::Error::from),
	};


	let known_path = get_known_path(path, cfg);
	let known_data = fs::read(&known_path);

	match (&input_data, &known_data) {
		(Ok(current), Ok(known)) => {
			let current_hashed = known_hash(current);

			if current_hashed.as_ref() == known.as_slice() {
				log::debug!(
					"{:?} has the same content as {:?}",
					&input_path,
					&known_path,
				);

				true
			} else {
				false
			}
		}
		_ => {
			// One or both reads failed
			false
		}
	}

}

#[inline(always)]
fn is_older_than(path: impl AsRef<Path>, time_ago: Duration) -> Result<bool> {
	let path = path.as_ref();

	let modified = fs::metadata(path)?.modified()?;

	let time_since = SystemTime::now().duration_since(modified)?;
	Ok(time_since > time_ago)
}

#[derive(Debug, thiserror::Error)]
pub enum CacheClearError {
	#[error("failed to serialize Knot cache-clear request: {0}")]
	SerializeRequest(#[source] serde_json::Error),

	#[error("failed to build Knot cache-clear request: {0}")]
	BuildRequest(#[source] hyper::http::Error),

	#[error("failed to send Knot cache-clear request: {0}")]
	SendRequest(#[source] hyper_util::client::legacy::Error),

	#[error("failed to read Knot cache-clear response body: {0}")]
	ReadResponseBody(#[source] hyper::Error),

	#[error("Knot Resolver cache-clear API returned {status}: {body}")]
	Api {
		status: hyper::StatusCode,
		body: String,
	},

	#[error("invalid JSON from Knot cache-clear API: {0}")]
	InvalidResponseJson(#[source] serde_json::Error),

	#[error("Knot cache-clear response is missing count") ]
	MissingCount,

	#[error(
		"failed to clear {count} Knot Resolver cache request(s)",
		count = .errors.len()
	)]
	Multiple {
		errors: Arc<[CacheClearError]>,
	},
}
async fn clear_knot_cache(
	mode: &CacheClear,
	sock: impl AsRef<Path>,
) -> Option<::core::result::Result<(), CacheClearError>> {
	let payloads: Vec<Value> = match mode {
		CacheClear::None => {
			return None;
		}

		CacheClear::All => {
			vec![serde_json::json!({})]
		}

		CacheClear::Specific(domains) => {
			domains
				.iter()
				.map(|v| {
					serde_json::json!({
						"name": v,
					})
				})
				.collect()
		}
	};

	let mut errors = Vec::new();

	for payload in payloads {
		if let Err(e) = clear_knot_cache_single(payload, sock.as_ref()).await {
			log::error!("{e}");
			errors.push(e);
		}
	}

	if errors.is_empty() {
		Some(Ok(()))
	} else {
		Some(Err(CacheClearError::Multiple {
			errors: errors.into(),
		}))
	}
}

async fn clear_knot_cache_single(
	payload: Value,
	sock: impl AsRef<Path>,
) -> ::core::result::Result<(), CacheClearError> {
	let json = serde_json::to_vec(&payload)
		.map_err(CacheClearError::SerializeRequest)?;

	let client = Client::unix();

	let uri: hyper::Uri = Uri::new(
		sock,
		"/cache/clear",
	)
	.into();

	let request = Request::post(uri)
		.header("Content-Type", "application/json")
		.body(Full::new(Bytes::from(json)))
		.map_err(CacheClearError::BuildRequest)?;

	let response = client
		.request(request)
		.await
		.map_err(CacheClearError::SendRequest)?;

	let status = response.status();

	let body = http_body_util::BodyExt::collect(response)
		.await
		.map_err(CacheClearError::ReadResponseBody)?
		.to_bytes();

	if !status.is_success() {
		return Err(CacheClearError::Api {
			status,
			body: String::from_utf8_lossy(&body).trim().to_owned(),
		});
	}

	let result: Value = serde_json::from_slice(&body)
		.map_err(CacheClearError::InvalidResponseJson)?;

	let count = result
		.get("count")
		.and_then(Value::as_u64)
		.ok_or(CacheClearError::MissingCount)?;

	log::info!(
		"Knot Resolver cache-clear request accepted; \
		 removed {count} cache entries in this round"
	);

	if result.get("chunk_limit").and_then(Value::as_bool) == Some(true) {
		log::info!(
			"Knot Resolver will continue clearing the remaining \
			 cache entries asynchronously"
		);
	}

	if result.get("not_apex").and_then(Value::as_bool) == Some(true) {
		log::warn!(
			"Knot Resolver reports that the cleared subtree is not a \
			 cached zone apex; some negative-cache proofs may remain"
		);
	}

	Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {

	let cfg = Config{
		resolv_conf: Path::new("/etc/resolv.conf"),
		run_dir: Path::new("/run/knot-nm-dns-update"),
		resolv_anti_rfc6761: Path::new("/etc/resolv.anti_rfc6761"),

		knot_resolver_last_started: Path::new("/run/knot-resolver/last_started"),

		resolv_nm_conf: Path::new("/run/NetworkManager/resolv.conf"),
	};

	env_logger::init();

	let cli = Cli::parse();

	log::info!("starting Knot Resolver NetworkManager DNS updater");

	// let (desired_nameservers, search_domains, resolv_conf_data) =
	let desired_resolv =
		read_resolv_conf(&cfg.resolv_nm_conf)?;



	let last_started_changed;
	let last_started_data = fs::read(&cfg.knot_resolver_last_started);
	match &last_started_data {
		Ok(data) => {
			last_started_changed = !matches_known(
				&cfg.knot_resolver_last_started,
				Some(&data),
				&cfg,
			);
		}
		_ => {
			last_started_changed = true
		}
	}



	let do_long_path = if !cli.fast_path {
		true
	} else {
		!matches_known(
			&cfg.resolv_nm_conf,
			Some(&desired_resolv.bytes),
			&cfg,
		)
		||
		last_started_changed
	};

	if do_long_path {

		if cli.copy_search {
			update_search_domains(
				&cfg.resolv_conf,
				&desired_resolv.search_domains,
			)?;
		}

		let anti_rfc6761 = read_anti_rfc6761(&cfg.resolv_anti_rfc6761)
			.with_context(|| {
				format!(
					"failed to read anti-RFC6761 configuration from {:?}",
					cfg.resolv_anti_rfc6761
				)
			})?;


		log::info!(
			"anti-RFC6761 forwarding domains: {:?}",
			anti_rfc6761
		);

		let desired_forward =
		build_forward_config(&desired_resolv.nameservers, &anti_rfc6761);

		let current_forward = get_knot_forward(&cli.kres_api_sock).await?;

		let desired_canonical = canonicalize_forward(&desired_forward)
			.context("failed to canonicalize desired forward configuration")?;

		let current_canonical = canonicalize_forward(&current_forward)
			.context("failed to canonicalize current Knot forward configuration")?;

		if current_canonical != desired_canonical {
			log::info!("Knot /forward differs from desired configuration");

			log::debug!(
				"current canonical /forward: {:#?}",
				current_canonical
			);

			log::debug!(
				"desired canonical /forward: {:#?}",
				desired_canonical
			);

			set_knot_forward(&desired_forward, &cli.kres_api_sock).await?;

			log::info!("Knot /forward updated successfully");

			let optres = clear_knot_cache(&cli.clear_cache, &cli.kres_api_sock).await;
			match optres {
				Some(Err(e)) => {
					log::error!("{}", e)
				}
				Some(Ok(_)) => {
					log::info!("cleared cache")
				}
				None => {
					log::debug!("cache clearing is disabled");
				}
			}


			log::info!("update fully finished");
		} else {
			log::info!("Knot /forward is already up to date");
		}



		write_known(&cfg.resolv_nm_conf, &desired_resolv.bytes, &cfg)?;

		log::debug!(
			"updated {:?} atomically",
			get_known_path(&cfg.resolv_nm_conf, &cfg),
		);



	} else {
		log::info!(
			"fast path: exiting early",
		);

		return Ok(());
	}


	// cleanup
	match &last_started_data {
		Ok(data) if last_started_changed => {
			write_known(
				&cfg.knot_resolver_last_started,
				&data,
				&cfg,
			)?;

			log::debug!(
				"updated {:?} atomically",
				get_known_path(&cfg.knot_resolver_last_started, &cfg),
			);
		}
		_ => {
			let should_delete = match is_older_than(
				get_known_path(&cfg.knot_resolver_last_started, &cfg),
				Duration::from_hours(24), ) {
				Ok(value) if !value => {
					false
				}
				Ok(value) if value => {
					true
				}
				Ok(_) => {
					true
				}
				Err(_) => {
					true
				}
			};
			if should_delete {
				match fs::remove_file(
					&get_known_path(
						&cfg.knot_resolver_last_started,
						&cfg,
					),
				) {
					Ok(()) => {}
					Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
					Err(err) => return Err(err.into()),
				}
			}
		}
	}


	Ok(())
}


