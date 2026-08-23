# Authentication

Authentication creates student accounts and issues access tokens after password
verification.

## Registration

1. `POST /api/auth/register` validates the name, email, and password with
   `UserRegisterRequest`.
2. `AuthUseCase.register` checks that the email is not already registered.
3. `password_utils.hash_password` stores a bcrypt hash, never the plaintext
   password.
4. `UserRepository.create_user` commits the new user.

## Login

1. `POST /api/auth/login` accepts an email and password.
2. The use case retrieves the account by normalized email.
3. `verify_password` compares the supplied password with the stored hash.
4. `jwt_utils.create_access_token` creates the signed token returned to the
   client.

The `ptas` terminal command uses the same endpoints through `PTASApiClient`, so
login activity is visible in the API terminal logs.

## Main code

- Route: `Backend/routes/auth_routes.py`
- Controller: `Backend/controllers/auth_controller.py`
- Business rules: `Backend/usecases/auth_usecase.py`
- Persistence: `Backend/repositories/user_repository.py`
- Password and token helpers: `Backend/utils/password_utils.py` and
  `Backend/utils/jwt_utils.py`

Passwords and bearer tokens must never be added to trace messages or exception
details.
