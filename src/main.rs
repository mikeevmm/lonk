use argh::FromArgs;
use figment::{providers::Format, Figment};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::PathBuf, str::FromStr, sync::Arc};
use tokio::sync::mpsc::UnboundedSender;
use validators::prelude::*;
use warp::{filters::BoxedFilter, hyper::StatusCode, Filter};

macro_rules! unwrap_or_unwrap_err {
    ($x:expr) => {
        match $x {
            Ok(x) => x,
            Err(y) => y,
        }
    };
}

#[derive(Serialize, Deserialize, Debug, Validator, Clone)]
#[validator(domain(ipv4(Allow), local(Allow), at_least_two_labels(Allow), port(Allow)))]
struct Url {
    domain: String,
    port: Option<u16>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
struct DbConfig {
    pub address: String,
}

impl Default for DbConfig {
    fn default() -> Self {
        Self {
            address: "redis://127.0.0.1".to_string(),
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
pub enum ServeRules {
    File(PathBuf),
    Dir(PathBuf),
}

impl ServeRules {
    pub fn to_filter(&self) -> BoxedFilter<(warp::fs::File,)> {
        match self {
            ServeRules::File(file) => warp::fs::file(file.clone()).boxed(),
            ServeRules::Dir(dir) => warp::fs::dir(dir.clone()).boxed(),
        }
    }
}

impl Default for ServeRules {
    fn default() -> Self {
        ServeRules::Dir(PathBuf::from_str("/etc/lonk/served").unwrap())
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

#[derive(Debug, Validator)]
#[validator(base64_url(padding(NotAllow)))]
struct Base64WithoutPaddingUrl(String);

impl FromStr for Base64WithoutPaddingUrl {
    type Err = <Self as ValidateString>::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse_str(s)
    }
}

#[derive(Debug)]
struct SlugDatabase {
    tx: UnboundedSender<SlugDbMessage>,
}

#[derive(Debug)]
enum SlugDbMessage {
    Add(Slug, Url),
}

impl SlugDatabase {
    fn from_client(client: redis::Client) -> Self {
        todo!()
    }

    fn insert_slug(&self, slug: Slug, url: Url) -> Result<(), ()> {
        self.tx
            .send(SlugDbMessage::Add(slug, url))
            .expect("Could not send message.");
        Ok(())
    }
}

struct SlugFactory {
    slug_length: usize,
    slug_chars: BTreeSet<char>,
}

#[derive(Debug)]
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
        todo!()
    }
}

fn shorten(
    slug_factory: &SlugFactory,
    db: &SlugDatabase,
    b64url: &str,
) -> Result<StatusCode, StatusCode> {
    let url = {
        let raw = base64::decode_config(b64url, base64::URL_SAFE_NO_PAD)
            .map_err(|_| warp::http::StatusCode::BAD_REQUEST)?;
        let url_str = std::str::from_utf8(&raw).map_err(|_| warp::http::StatusCode::BAD_REQUEST)?;
        Url::parse_str(url_str).map_err(|_| warp::http::StatusCode::BAD_REQUEST)?
    };

    let new_slug = slug_factory.generate();

    Ok(warp::http::StatusCode::OK)
}

#[tokio::main]
async fn serve() {
    // Read configuration
    let config_file = std::env::var("LONK_CONFIG").unwrap_or("lonk.json".to_string());
    let config: Config = Figment::new()
        .merge(figment::providers::Json::file(&config_file))
        .extract()
        .expect("Could not parse configuration file.");

    // Create slug factory
    let slug_factory = Arc::new(SlugFactory::from_rules(config.slug_rules));

    // Initialize database
    let db = {
        let client = redis::Client::open(config.db.address).expect("Error opening Redis database.");
        //let conn = Connection::open(config.db_location).expect("Could not open database.");
        Arc::new(SlugDatabase::from_client(client))
    };

    // GET /
    let homepage = warp::path::end().and(config.serve_rules.to_filter());

    // GET /shorten/:Base64WithoutPaddingUrl
    let shorten = warp::path!("shorten" / Base64WithoutPaddingUrl).map({
        move |link: Base64WithoutPaddingUrl| {
            warp::reply::with_status(
                warp::reply(),
                unwrap_or_unwrap_err!(shorten(&slug_factory, &db, &link.0)),
            )
        }
    });

    // GET /l/:Slug
    let link = warp::path("l")
        .and(warp::path::param())
        .map(|slug: String| warp::reply());

    let routes = warp::get().and(homepage.or(shorten).or(link));

    warp::serve(routes).run(([127, 0, 0, 1], 8892)).await;
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
