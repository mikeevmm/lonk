use argh::FromArgs;
use async_object_pool::Pool;
use core::panic;
use rand::prelude::*;
use redis::Commands;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, net::IpAddr, path::PathBuf, str::FromStr, sync::Arc};
use tokio::sync;
use validators::prelude::*;
use warp::{filters::BoxedFilter, http::Response, hyper::StatusCode, Filter};

macro_rules! clone {
    (mut $y:ident) => {
        let mut $y = $y.clone();
    };
    ($y:ident) => {
        let $y = $y.clone();
    };
    ($y:ident, $($x:ident),+) => {
        clone!($y);
        clone!($($x),+);
    };
}

#[cfg(debug_assertions)]
macro_rules! debuginfo {
    ($log:literal) => {
        $log
    };
    ($log:literal,$alt:literal) => {
        $log
    };
}

#[cfg(not(debug_assertions))]
macro_rules! debuginfo {
    ($log:literal) => {
        "Internal error."
    };
    ($log:literal,$alt:literal) => {
        $alt
    };
}

#[cfg(debug_assertions)]
macro_rules! ifdbg {
    ($expr:expr) => {
        $expr;
    };
}

#[cfg(not(debug_assertions))]
macro_rules! ifdbg {
    ($expr:expr) => {
        ()
    };
}

#[derive(Validator)]
#[validator(http_url(local(Allow)))]
#[derive(Clone, Debug)]
pub struct HttpUrl {
    url: validators::url::Url,
    is_https: bool,
}

impl std::fmt::Display for HttpUrl {
    fn fmt(&self, f: &mut validators_prelude::Formatter<'_>) -> std::fmt::Result {
        self.url.fmt(f)
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
struct DbConfig {
    address: String,
    expire_seconds: usize,
}

impl Default for DbConfig {
    fn default() -> Self {
        Self {
            address: "redis://127.0.0.1:6379".to_string(),
            expire_seconds: 259200, // 3 days
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct SlugRules {
    pub length: usize,
    pub chars: String,
}

impl Default for SlugRules {
    fn default() -> Self {
        Self {
            length: 5,
            chars: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-".to_string(),
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum ServeDirRules {
    File(PathBuf),
    Dir(PathBuf),
}

impl ServeDirRules {
    pub fn to_filter(&self) -> BoxedFilter<(warp::fs::File,)> {
        match self {
            ServeDirRules::File(file) => warp::fs::file(file.clone()).boxed(),
            ServeDirRules::Dir(dir) => warp::fs::dir(dir.clone()).boxed(),
        }
    }
}

impl Default for ServeDirRules {
    fn default() -> Self {
        ServeDirRules::Dir(PathBuf::from_str("/etc/lonk/served").unwrap())
    }
}

#[derive(Serialize, Deserialize, Debug, Validator, Clone)]
#[validator(ip(local(Allow), port(Must)))]
struct ServeAddr {
    ip: IpAddr,
    port: u16,
}

impl Default for ServeAddr {
    fn default() -> Self {
        Self {
            ip: [127, 0, 0, 1].into(),
            port: 8080,
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
struct ServeRules {
    dir: ServeDirRules,
    addr: ServeAddr,
}

impl Default for ServeRules {
    fn default() -> Self {
        Self {
            dir: Default::default(),
            addr: ServeAddr::default(),
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
struct Config {
    pub db: DbConfig,
    pub slug_rules: SlugRules,
    pub serve_rules: ServeRules,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            db: Default::default(),
            slug_rules: Default::default(),
            serve_rules: Default::default(),
        }
    }
}

#[derive(Debug)]
struct SlugDatabase {
    tx: sync::mpsc::UnboundedSender<SlugDbMessage>,
}

#[derive(Clone, Debug)]
enum AddResult {
    Success(Slug),
    Fail,
}

#[derive(Clone, Debug)]
enum GetResult {
    Found(HttpUrl),
    NotFound,
    InternalError,
}

enum SlugDbMessage {
    Add(Slug, HttpUrl, sync::oneshot::Sender<AddResult>),
    Get(Slug, sync::oneshot::Sender<GetResult>),
}

impl core::fmt::Debug for SlugDbMessage {
    fn fmt(&self, f: &mut validators_prelude::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Add(arg0, arg1, _) => f
                .debug_tuple("Add")
                .field(arg0)
                .field(arg1)
                .field(&"oneshot::Sender<AddResult>")
                .finish(),
            SlugDbMessage::Get(arg0, _) => f
                .debug_tuple("Get")
                .field(arg0)
                .field(&"oneshot::Sender<Url>")
                .finish(),
        }
    }
}

impl SlugDatabase {
    fn from_client(client: redis::Client, expire_seconds: usize) -> Self {
        let (tx, mut rx) = sync::mpsc::unbounded_channel::<SlugDbMessage>();

        tokio::spawn(async move {
            let pool = Arc::new(sync::Mutex::new(Pool::new(100)));

            while let Some(msg) = { rx.recv().await } {
                let mut connection = {
                    (*pool.lock().await)
                        .take_or_create(|| {
                            client
                                .get_connection()
                                .expect("Could not open connection to Redis server.")
                        })
                        .await
                };

                let pool = pool.clone();
                tokio::spawn(async move {
                    match msg {
                        SlugDbMessage::Add(requested_slug, url, response_channel) => {
                            let url_str = url.to_string();
                            // Check that the URL is not already present in the DB
                            // This is, to some extent, a protection against collision attacks.
                            match connection
                                .get::<String, Option<String>>(format!("url:{}", url_str))
                            {
                                Ok(Some(slug)) => {
                                    // The URL was already present, just return that.
                                    response_channel.send(AddResult::Success(Slug(slug))).ok();
                                    return;
                                }
                                Err(err) => {
                                    response_channel.send(AddResult::Fail).ok();
                                    ifdbg!(eprintln!("{}", err));
                                    return;
                                }
                                _ => {} // Ok(None); continue with insertion
                            };

                            // The URL is not present in the database; insert it.
                            let add_result = connection.set_ex::<String, String, ()>(
                                format!("slug:{}", requested_slug.0),
                                url_str.clone(),
                                expire_seconds,
                            );
                            if add_result.is_ok() {
                                connection
                                    .set_ex::<String, String, ()>(
                                        format!("url:{}", url_str),
                                        requested_slug.0.clone(),
                                        expire_seconds,
                                    )
                                    .ok(); // If this failed we have no way of correcting for it.
                            }
                            response_channel
                                .send(match add_result {
                                    Ok(_) => AddResult::Success(requested_slug),
                                    Err(err) => {
                                        ifdbg!(eprintln!("{}", err));
                                        AddResult::Fail
                                    }
                                })
                                .ok(); // If the receiver has hung up there's nothing we can do.
                        }
                        SlugDbMessage::Get(slug, response_channel) => {
                            let result: Result<Option<String>, _> =
                                connection.get(format!("slug:{}", slug.0));
                            match result {
                                Ok(Some(url)) => response_channel.send(GetResult::Found(
                                    HttpUrl::parse_string(url)
                                        .expect("Mismatched URL in the database."),
                                )),
                                Ok(None) => response_channel.send(GetResult::NotFound),
                                Err(err) => {
                                    ifdbg!(eprintln!("{}", err));
                                    response_channel.send(GetResult::InternalError)
                                }
                            }
                            .ok(); // If the receiver has hung up there's nothing we can do.
                        }
                    }

                    (*pool.lock().await).put(connection).await;
                });
            }
        });

        SlugDatabase { tx }
    }

    fn insert_slug(
        &self,
        requested_slug: Slug,
        url: HttpUrl,
    ) -> sync::oneshot::Receiver<AddResult> {
        let (tx, rx) = sync::oneshot::channel();
        self.tx
            .send(SlugDbMessage::Add(requested_slug, url, tx))
            .expect("The SlugDbMessage channel is unexpectedly closed.");
        rx
    }

    async fn get_slug(&self, slug: Slug) -> Result<Option<HttpUrl>, ()> {
        let (tx, rx) = sync::oneshot::channel();
        self.tx
            .send(SlugDbMessage::Get(slug, tx))
            .expect("The SlugDbMessage channel is unexpectedly closed.");
        match rx
            .await
            .expect("The query channel was unexpectedly dropped.")
        {
            GetResult::Found(url) => Ok(Some(url)),
            GetResult::NotFound => Ok(None),
            GetResult::InternalError => Err(()),
        }
    }
}

struct SlugFactory {
    slug_length: usize,
    slug_chars: BTreeSet<char>,
    slug_chars_indexable: Vec<char>,
}

#[derive(Clone, Debug)]
struct Slug(String);

enum InvalidSlug {
    TooLong,
    BadChar,
}

impl SlugFactory {
    fn from_rules(rules: SlugRules) -> Self {
        let mut slug_chars = BTreeSet::<char>::new();
        slug_chars.extend(rules.chars.chars());

        SlugFactory {
            slug_length: rules.length,
            slug_chars,
            slug_chars_indexable: rules.chars.chars().collect(),
        }
    }

    fn parse_str(&self, s: &str) -> Result<Slug, InvalidSlug> {
        for (i, char) in s.chars().enumerate() {
            if i >= self.slug_length {
                return Err(InvalidSlug::TooLong);
            }

            if !self.slug_chars.contains(&char) {
                return Err(InvalidSlug::BadChar);
            }
        }

        Ok(Slug(s.to_string()))
    }

    fn generate(&self) -> Slug {
        // Generate indices then map
        let distribution = rand::distributions::Uniform::new(0, self.slug_chars_indexable.len());
        let slug_str = distribution
            .sample_iter(rand::thread_rng())
            .take(self.slug_length)
            .map(|i| self.slug_chars_indexable[i])
            .collect::<String>();
        Slug(slug_str)
    }
}

async fn shorten(
    slug_factory: &SlugFactory,
    db: &SlugDatabase,
    b64str: &str,
) -> Result<Slug, (StatusCode, String)> {
    let url = {
        let unencoded_bytes =
            base64::decode_config(b64str, base64::URL_SAFE_NO_PAD).map_err(|_| {
                (
                    warp::http::StatusCode::BAD_REQUEST,
                    debuginfo!("Could not decode base64 str.", "Invalid URL Base64.").into(),
                )
            })?;
        let url_str = std::str::from_utf8(&unencoded_bytes[..]).map_err(|_| {
            (
                warp::http::StatusCode::BAD_REQUEST,
                debuginfo!(
                    "Parsed bytes of base64 str, but could not decode as UTF8.",
                    "Invalid URL Base64."
                )
                .into(),
            )
        })?;
        HttpUrl::parse_str(url_str)
            .map_err(|_| (warp::http::StatusCode::BAD_REQUEST, "Invalid URL.".into()))?
    };

    let new_slug = slug_factory.generate();
    let insert_result = db.insert_slug(new_slug, url).await;
    match insert_result {
        Ok(result) => match result {
            AddResult::Success(slug) => Ok(slug),
            AddResult::Fail => Err((
                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                debuginfo!("Got insertion response, but it was error.").into(),
            )),
        },
        Err(e) => {
            ifdbg!(eprintln!("{}", e));
            Err((
                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                debuginfo!("Receiver error on response of slug insertion.").into(),
            ))
        }
    }
}

async fn insert_slug(
    b64str: &str,
    slug_factory: &SlugFactory,
    db: &SlugDatabase,
) -> Response<String> {
    match shorten(&slug_factory, &db, b64str).await {
        Ok(slug) => Response::builder().body(format!("{}", slug.0)).unwrap(),
        Err((status, message)) => Response::builder().status(status).body(message).unwrap(),
    }
}

#[tokio::main]
async fn serve() {
    // Read configuration

    let config: Config = {
        let config_file_name = std::env::var("LONK_CONFIG").unwrap_or("lonk.json".to_string());
        let config_file = std::fs::File::open(config_file_name.clone()).unwrap_or_else(|err| {
            match err.kind() {
                std::io::ErrorKind::NotFound => {
                    panic!("Configuration file {} does not exist.", config_file_name)
                }
                std::io::ErrorKind::PermissionDenied => {
                    panic!("Read permission to {} was denied.", config_file_name)
                }
                _ => panic!(
                    "Error when trying to read configuration file {}: {}",
                    config_file_name, err
                ),
            };
        });
        let config_buf = std::io::BufReader::new(config_file);
        serde_json::from_reader(config_buf).unwrap_or_else(|err| match err.classify() {
            serde_json::error::Category::Io => panic!("IO error when reading configuration file."),
            serde_json::error::Category::Syntax => panic!(
                "Configuration file is syntactically incorrect.
                    See {}:line {}, column {}.",
                &config_file_name,
                err.line(),
                err.column()
            ),
            serde_json::error::Category::Data => panic!(
                "Error deserializing configuration file; expected different data type.
                    See {}:line {}, column {}.",
                &config_file_name,
                err.line(),
                err.column()
            ),
            serde_json::error::Category::Eof => {
                panic!("Unexpected end of file when reading configuration file.")
            }
        })
    };

    // Create slug factory
    let slug_factory = SlugFactory::from_rules(config.slug_rules);

    // Initialize database
    let db = {
        let client = redis::Client::open(config.db.address).expect("Error opening Redis database.");
        SlugDatabase::from_client(client, config.db.expire_seconds)
    };

    // We leak the slug factory and the database, because we know that these
    // will live forever, and want them to have 'static lifetime so that warp is
    // happy.
    let slug_factory: &'static SlugFactory = Box::leak(Box::new(slug_factory));
    let db: &'static SlugDatabase = Box::leak(Box::new(db));

    // GET /
    let homepage = warp::path::end().and(config.serve_rules.dir.to_filter());

    // POST /shorten/ with argument link:Base64WithoutPaddingUrl
    let shorten = warp::post()
        .and(warp::path("shorten"))
        .and(warp::body::content_length_limit(1024))
        .and(warp::body::bytes())
        .then(move |body: warp::hyper::body::Bytes| async move {
            let b64str = std::str::from_utf8(&body[..]);
            if b64str.is_err() {
                return Response::builder()
                    .status(warp::http::StatusCode::BAD_REQUEST)
                    .body(String::new())
                    .unwrap();
            }
            insert_slug(b64str.unwrap(), slug_factory, db).await
        });

    // GET /l/:Slug
    let link = warp::path("l")
        .and(warp::path::param())
        .map(|slug: String| warp::reply());

    let get_routes = warp::get().and(homepage.or(link));
    let post_routes = warp::post().and(shorten);
    let routes = get_routes.or(post_routes);

    println!(
        "Now serving lonk at IP {}, port {}!",
        config.serve_rules.addr.ip, config.serve_rules.addr.port
    );
    warp::serve(routes)
        .run((config.serve_rules.addr.ip, config.serve_rules.addr.port))
        .await;

    unreachable!("The warp server runs forever.")
}

#[derive(FromArgs, PartialEq, Debug)]
/// Start lonk.
struct Run {
    /// write a default configuration to stdout and quit
    #[argh(switch)]
    print_default_config: bool,
}

fn main() {
    let run = argh::from_env::<Run>();

    if run.print_default_config {
        println!(
            "{}",
            serde_json::to_string_pretty(&Config::default())
                .expect("Default configuration should always be JSON serializable")
        );
    } else {
        serve();
    }
}
