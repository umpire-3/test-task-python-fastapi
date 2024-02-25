from datetime import datetime, timedelta, timezone
from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlmodel import SQLModel, Session, create_engine, select

from jose import JWTError, jwt
from passlib.context import CryptContext

from models import (
    User, UserCreate, UserRead, UserUpdate,
    Organization, OrganizationCreate, OrganizationRead, OrganizationUpdate
)


SECRET_KEY = 'c4f3fb9df021301c21b27c46a1dd7870384ae35f1b682bd4abc29c8f1815ed8e'
ALGORITHM = 'HS256'
ACCESS_TOKEN_EXPIRE_MINUTES = 30


credentials = {
    'username': 'admin',
    'hashed_password': '$2b$12$A2r8ZDplhuizFre2A45wz.gvk46IM0uo9ZacFuP/rZxfmp7fXtI9e'
}

pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')
    

sqlite_file_name = 'database.db'
sqlite_url = f'sqlite:///{sqlite_file_name}'

connect_args = {'check_same_thread': False}
engine = create_engine(sqlite_url, echo=True, connect_args=connect_args)


def create_db_and_tables():
    SQLModel.metadata.create_all(engine)


def authenticate_user(username: str, password: str):
    if username != credentials['username']:
        return False
    if not pwd_context.verify(password, credentials['hashed_password']):
        return False
    return True


def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    if username != credentials['username']:
        raise credentials_exception
    return True


def get_session():
    with Session(engine) as session:
        yield session

app = FastAPI()


@app.on_event('startup')
def on_startup():
    create_db_and_tables()


@app.post('/token')
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    if not authenticate_user(form_data.username, form_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Incorrect username or password',
            headers={'WWW-Authenticate': 'Bearer'}
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={'sub': credentials['username']}, expires_delta=access_token_expires
    )
    return {'access_token': access_token, 'token_type': 'bearer'}


@app.post('/users/', response_model=UserRead)
def create_user(user: UserCreate, session: Session = Depends(get_session), verified: bool = Depends(verify_token)):
    db_user = User.model_validate(user)
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    return db_user


@app.get('/users/', response_model=list[UserRead])
def read_users(
        offset: int = 0, 
        limit: int = Query(default=100, le=100), 
        session: Session = Depends(get_session), 
        verified: bool = Depends(verify_token)
    ):
    users = session.exec(select(User).offset(offset).limit(limit)).all()
    return users


@app.get('/users/{user_id}', response_model=UserRead)
def read_user(user_id: int, session: Session = Depends(get_session), verified: bool = Depends(verify_token)):
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail='User not found')
    return user


@app.patch('/users/{user_id}', response_model=UserRead)
def update_user(user_id: int, user: UserUpdate, session: Session = Depends(get_session), verified: bool = Depends(verify_token)):
    db_user = session.get(User, user_id)
    if not db_user:
        raise HTTPException(status_code=404, detail='User not found')
    user_data = user.model_dump(exclude_unset=True)
    db_user.sqlmodel_update(user_data)
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    return db_user


@app.delete('/users/{user_id}')
def delete_user(user_id: int, session: Session = Depends(get_session), verified: bool = Depends(verify_token)):
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail='User not found')
    session.delete(user)
    session.commit()
    return {'ok': True}


@app.post('/organizations/', response_model=OrganizationRead)
def create_organization(organization: OrganizationCreate, session: Session = Depends(get_session), verified: bool = Depends(verify_token)):
    db_organization = Organization.model_validate(organization)
    session.add(db_organization)
    session.commit()
    session.refresh(db_organization)
    return db_organization


@app.get('/organizations/', response_model=list[OrganizationRead])
def read_organizations(
        offset: int = 0, 
        limit: int = Query(default=100, le=100), 
        session: Session = Depends(get_session), 
        verified: bool = Depends(verify_token)
    ):
    organizations = session.exec(select(Organization).offset(offset).limit(limit)).all()
    return organizations


@app.get('/organizations/{organization_id}', response_model=OrganizationRead)
def read_organization(organization_id: int, session: Session = Depends(get_session), verified: bool = Depends(verify_token)):
    organization = session.get(Organization, organization_id)
    if not organization:
        raise HTTPException(status_code=404, detail='Organization not found')
    return organization


@app.patch('/organizations/{organization_id}', response_model=OrganizationRead)
def update_organization(
        organization_id: int, 
        organization: OrganizationUpdate, 
        session: Session = Depends(get_session), 
        verified: bool = Depends(verify_token)
    ):
    db_organization = session.get(Organization, organization_id)
    if not db_organization:
        raise HTTPException(status_code=404, detail='Organization not found')
    organization_data = organization.model_dump(exclude_unset=True)
    db_organization.sqlmodel_update(organization_data)
    session.add(db_organization)
    session.commit()
    session.refresh(db_organization)
    return db_organization


@app.delete('/organizations/{organization_id}')
def delete_organization(organization_id: int, session: Session = Depends(get_session), verified: bool = Depends(verify_token)):
    organization = session.get(Organization, organization_id)
    if not organization:
        raise HTTPException(status_code=404, detail='Organization not found')
    session.delete(organization)
    session.commit()
    return {'ok': True}
