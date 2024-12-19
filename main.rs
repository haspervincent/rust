use actix_web::{web, App, HttpServer, Responder, HttpResponse};
use actix_cors::Cors;
use bcrypt::{hash, DEFAULT_COST};
use serde::{Serialize, Deserialize};

#[derive(Deserialize)]
struct RegisterRequest {
    email: String,
    password: String,
    password_confirmation: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Serialize)]
struct SuccessResponse {
    message: String,
}

fn validate_email(email: &str) -> Result<(), String> {
    if email.contains('@') {
        Ok(())
    } else {
        Err("invalid email address".to_string())
    }
}

fn validate_password(password: &str) -> Result<(), String> {
    if password.len() < 8 {
        return Err("password must be at least 8 characters long".to_string());
    }
    if !password.chars().any(|c| c.is_uppercase()) {
        return Err("password must contain at least one uppercase letter".to_string());
    }
    if !password.chars().any(|c| c.is_lowercase()) {
        return Err("password must contain at least one lowercase letter".to_string());
    }
    if !password.chars().any(|c| c.is_digit(10)) {
        return Err("password must contain at least one digit".to_string());
    }
    if !password.chars().any(|c| !c.is_alphanumeric()) {
        return Err("password must contain at least one special character".to_string());
    }
    Ok(())
}

fn validate_passwords_match(password: &str, password_confirmation: &str) -> Result<(), String> {
    if password == password_confirmation {
        Ok(())
    } else {
        Err("passwords do not match".to_string())
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        let cors = Cors::default()
            .allowed_origin("http://localhost:3000")
            .allowed_methods(vec!["GET", "POST"])
            .allowed_headers(vec!["Content-Type", "Authorization"])
            .supports_credentials();

        App::new()
            .wrap(cors)
            .service(web::scope("/auth")
                .route("/register", web::post().to(register)))
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}

async fn register(req: web::Json<RegisterRequest>) -> impl Responder {
    if let Err(e) = validate_email(&req.email) {
        return HttpResponse::BadRequest().json(ErrorResponse { 
            error: e,
        });
    }
    if let Err(e) = validate_password(&req.password) {
        return HttpResponse::BadRequest().json(ErrorResponse { 
            error: e,
        });
    }
    if let Err(e) = validate_passwords_match(&req.password, &req.password_confirmation) {
        return HttpResponse::BadRequest().json(ErrorResponse { 
            error: e,
        });
    }

    let hashed_password = match hash(&req.password, DEFAULT_COST) {
        Ok(hashed) => hashed,
        Err(_) => return HttpResponse::InternalServerError().json(ErrorResponse {
            error: "internal server error".to_string(),
        }),
    };

    HttpResponse::Ok().json(SuccessResponse {
        message: "successfully created account".to_string(),
    })
}

