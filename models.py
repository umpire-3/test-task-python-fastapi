from typing import Optional

from sqlmodel import SQLModel, Field, Relationship


class OrganizationBase(SQLModel):
    name: str
    motto: str


class Organization(OrganizationBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)

    users: list['User'] = Relationship(back_populates='organization')


class OrganizationRead(OrganizationBase):
    id: int


class OrganizationCreate(OrganizationBase):
    pass


class OrganizationUpdate(SQLModel):
    name: Optional[str] = None
    motto: Optional[str] = None


class UserBase(SQLModel):
    name: str
    last_name: str
    email: str
    age: int
    organization_id: Optional[int] = Field(default=None, foreign_key="organization.id")


class User(UserBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)

    organization: Optional[Organization] = Relationship(back_populates="users")


class UserRead(UserBase):
    id: int


class UserCreate(UserBase):
    pass


class UserUpdate(SQLModel):
    name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[str] = None
    age: Optional[int] = None
    organization_id: Optional[int] = None