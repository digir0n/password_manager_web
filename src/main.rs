use actix_web::{
    web, App, HttpServer, HttpResponse, Result, middleware::Logger
};
use askama::Template;
use rusqlite::{Connection, params};
use bcrypt::{hash, verify, DEFAULT_COST};
use uuid::Uuid;
use std::sync::Mutex;

type Db = Mutex<Connection>;

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    sites: Vec<Site>,
    search_query: String,
    message: Option<String>,
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate {
    error: Option<String>,
}

#[derive(Template)]
#[template(path = "add_site.html")]
struct AddSiteTemplate {
    message: Option<String>,
    edit_site: Option<Site>,
}

#[derive(serde::Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

#[derive(serde::Deserialize, serde::Serialize, Clone)]
struct Site {
    id: Option<String>,
    name: String,
    url: String,
    username: String,
    password: String,
    notes: String,
}

#[derive(serde::Deserialize)]
struct SiteForm {
    id: Option<String>,
    name: String,
    url: String,
    username: String,
    password: String,
    notes: String,
}

#[derive(serde::Deserialize)]
struct SearchQuery {
    q: Option<String>,
}

fn init_db() -> Result<Connection, rusqlite::Error> {
    let conn = Connection::open("sites.db")?;
    
    // Create users table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )",
        [],
    )?;
    
    // Create sites table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS sites (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            url TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            notes TEXT,
            user_id TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )",
        [],
    )?;
    
    // Create default admin user if it doesn't exist
    {
        let mut stmt = conn.prepare("SELECT COUNT(*) FROM users WHERE username = 'admin'")?;
        let count: i64 = stmt.query_row([], |row| row.get(0))?;
        drop(stmt);
        
        if count == 0 {
            let user_id = Uuid::new_v4().to_string();
            let password_hash = hash("admin123", DEFAULT_COST)
                .map_err(|e| rusqlite::Error::InvalidParameterName(e.to_string()))?;
            conn.execute(
                "INSERT INTO users (id, username, password_hash) VALUES (?1, ?2, ?3)",
                params![user_id, "admin", password_hash],
            )?;
            println!("Default user created: admin/admin123");
        }
    }
    
    Ok(conn)
}

async fn index(
    db: web::Data<Db>,
    query: web::Query<SearchQuery>,
) -> Result<HttpResponse> {
    let conn = db.lock().unwrap();
    let search_query = query.q.clone().unwrap_or_default();
    // Resolve admin user's ID
    let admin_user_id: String = conn
        .query_row("SELECT id FROM users WHERE username = 'admin'", [], |row| row.get(0))
        .unwrap();
    
    let sql = if search_query.is_empty() {
        "SELECT id, name, url, username, password, notes FROM sites WHERE user_id = ?1 ORDER BY name COLLATE NOCASE"
    } else {
        "SELECT id, name, url, username, password, notes FROM sites WHERE user_id = ?1 AND (name LIKE ?2 OR url LIKE ?2 OR username LIKE ?2) ORDER BY name COLLATE NOCASE"
    };
    
    let mut stmt = conn.prepare(sql).unwrap();
    
    let map_site = |row: &rusqlite::Row| -> rusqlite::Result<Site> {
        Ok(Site {
            id: row.get(0)?,
            name: row.get(1)?,
            url: row.get(2)?,
            username: row.get(3)?,
            password: row.get(4)?,
            notes: row.get(5)?,
        })
    };

    let site_iter = if search_query.is_empty() {
        stmt.query_map([&admin_user_id], map_site).unwrap()
    } else {
        let search_pattern = format!("%{}%", search_query);
        stmt.query_map((&admin_user_id, &search_pattern), map_site).unwrap()
    };
    
    let mut sites = Vec::new();
    for site in site_iter {
        sites.push(site.unwrap());
    }
    
    let template = IndexTemplate { 
        sites, 
        search_query: search_query.clone(),
        message: None 
    };
    let body = template.render().unwrap();
    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}

async fn login_page() -> Result<HttpResponse> {
    let template = LoginTemplate { error: None };
    let body = template.render().unwrap();
    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}

async fn login(
    form: web::Form<LoginForm>,
    db: web::Data<Db>,
) -> Result<HttpResponse> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare("SELECT password_hash FROM users WHERE username = ?1").unwrap();
    
    let result: Result<String, rusqlite::Error> = stmt.query_row([&form.username], |row| row.get(0));
    
    match result {
        Ok(password_hash) => {
            if verify(&form.password, &password_hash).unwrap_or(false) {
                Ok(HttpResponse::SeeOther()
                    .append_header(("Location", "/"))
                    .finish())
            } else {
                let template = LoginTemplate { 
                    error: Some("Invalid password".to_string()) 
                };
                let body = template.render().unwrap();
                Ok(HttpResponse::Ok().content_type("text/html").body(body))
            }
        }
        Err(_) => {
            let template = LoginTemplate { 
                error: Some("User not found".to_string()) 
            };
            let body = template.render().unwrap();
            Ok(HttpResponse::Ok().content_type("text/html").body(body))
        }
    }
}

async fn add_site_page() -> Result<HttpResponse> {
    let template = AddSiteTemplate { 
        message: None,
        edit_site: None 
    };
    let body = template.render().unwrap();
    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}

async fn edit_site_page(
    path: web::Path<String>,
    db: web::Data<Db>,
) -> Result<HttpResponse> {
    let id = path.into_inner();
    let conn = db.lock().unwrap();
    
    let mut stmt = conn.prepare("SELECT id, name, url, username, password, notes FROM sites WHERE id = ?1").unwrap();
    
    let site_result = stmt.query_row([&id], |row| {
        Ok(Site {
            id: row.get(0)?,
            name: row.get(1)?,
            url: row.get(2)?,
            username: row.get(3)?,
            password: row.get(4)?,
            notes: row.get(5)?,
        })
    });
    
    match site_result {
        Ok(site) => {
            let template = AddSiteTemplate { 
                message: None,
                edit_site: Some(site) 
            };
            let body = template.render().unwrap();
            Ok(HttpResponse::Ok().content_type("text/html").body(body))
        }
        Err(_) => {
            Ok(HttpResponse::SeeOther()
                .append_header(("Location", "/"))
                .finish())
        }
    }
}

async fn create_site(
    form: web::Form<SiteForm>,
    db: web::Data<Db>,
) -> Result<HttpResponse> {
    let conn = db.lock().unwrap();
    let id = Uuid::new_v4().to_string();
    let admin_user_id: String = conn
        .query_row("SELECT id FROM users WHERE username = 'admin'", [], |row| row.get(0))
        .unwrap();
    
    conn.execute(
        "INSERT INTO sites (id, name, url, username, password, notes, user_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![id, &form.name, &form.url, &form.username, &form.password, &form.notes, admin_user_id],
    ).unwrap();
    
    Ok(HttpResponse::SeeOther()
        .append_header(("Location", "/"))
        .finish())
}

async fn update_site(
    form: web::Form<SiteForm>,
    db: web::Data<Db>,
) -> Result<HttpResponse> {
    if let Some(id) = &form.id {
        let conn = db.lock().unwrap();
        
        conn.execute(
            "UPDATE sites SET name = ?1, url = ?2, username = ?3, password = ?4, notes = ?5 WHERE id = ?6",
            params![&form.name, &form.url, &form.username, &form.password, &form.notes, id],
        ).unwrap();
    }
    
    Ok(HttpResponse::SeeOther()
        .append_header(("Location", "/"))
        .finish())
}

async fn delete_site(
    path: web::Path<String>,
    db: web::Data<Db>,
) -> Result<HttpResponse> {
    let id = path.into_inner();
    let conn = db.lock().unwrap();
    
    conn.execute("DELETE FROM sites WHERE id = ?1", params![id]).unwrap();
    
    Ok(HttpResponse::SeeOther()
        .append_header(("Location", "/"))
        .finish())
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    
    // Initialize database
    let conn = init_db().expect("Failed to initialize database");
    let db = web::Data::new(Mutex::new(conn));
    let static_dir: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/static");
    
    println!("Starting server at http://localhost:8080");
    println!("Default login: admin / admin123");
    
    HttpServer::new(move || {
        App::new()
            .app_data(db.clone())
            .wrap(Logger::default())
            .service(actix_files::Files::new("/static", static_dir).show_files_listing())
            .route("/", web::get().to(index))
            .route("/login", web::get().to(login_page))
            .route("/login", web::post().to(login))
            .route("/add", web::get().to(add_site_page))
            .route("/edit/{id}", web::get().to(edit_site_page))
            .route("/sites", web::post().to(create_site))
            .route("/sites/update", web::post().to(update_site))
            .route("/sites/{id}/delete", web::post().to(delete_site))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}