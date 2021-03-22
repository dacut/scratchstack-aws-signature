use std::{
    error::Error,
    fmt::{Display, Formatter, Result as FmtResult},
};

use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub enum PrincipalError {
    InvalidPartition,
    InvalidAccountId,
    InvalidPath,
    InvalidName,
}

impl Error for PrincipalError {}

impl Display for PrincipalError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::InvalidPartition => write!(f, "InvalidPartition"),
            Self::InvalidAccountId => write!(f, "InvalidAccountId"),
            Self::InvalidPath => write!(f, "InvalidPath"),
            Self::InvalidName => write!(f, "InvalidName"),
        }
    }
}

/// Principal for a given access key
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Principal {
    /// The partition this principal exists in.
    pub partition: String,

    /// Principal type -- role, assumed role, service, etc.
    pub principal_type: PrincipalType,
}

impl Principal {
    pub fn assumed_role<S1, S2, S3, S4, S5>(
        partition: S1,
        account_id: S2,
        path: S3,
        name: S4,
        session_name: S5,
    ) -> Result<Self, PrincipalError>
    where
        S1: Into<String>,
        S2: Into<String>,
        S3: Into<String>,
        S4: Into<String>,
        S5: Into<String>,
    {
        Ok(Self {
            partition: validate_partition(partition)?,
            principal_type: PrincipalType::AssumedRole(IAMAssumedRoleDetails::new(
                account_id,
                path,
                name,
                session_name,
            )?),
        })
    }

    pub fn group<S1, S2, S3, S4, S5>(
        partition: S1,
        account_id: S2,
        path: S3,
        name: S4,
        group_id: S5,
    ) -> Result<Self, PrincipalError>
    where
        S1: Into<String>,
        S2: Into<String>,
        S3: Into<String>,
        S4: Into<String>,
        S5: Into<String>,
    {
        Ok(Self {
            partition: validate_partition(partition)?,
            principal_type: PrincipalType::Group(IAMGroupDetails::new(account_id, path, name, group_id)?),
        })
    }

    pub fn role<S1, S2, S3, S4, S5>(
        partition: S1,
        account_id: S2,
        path: S3,
        name: S4,
        role_id: S5,
    ) -> Result<Self, PrincipalError>
    where
        S1: Into<String>,
        S2: Into<String>,
        S3: Into<String>,
        S4: Into<String>,
        S5: Into<String>,
    {
        Ok(Self {
            partition: validate_partition(partition)?,
            principal_type: PrincipalType::Role(IAMRoleDetails::new(account_id, path, name, role_id)?),
        })
    }

    pub fn user<S1, S2, S3, S4, S5>(
        partition: S1,
        account_id: S2,
        path: S3,
        name: S4,
        user_id: S5,
    ) -> Result<Self, PrincipalError>
    where
        S1: Into<String>,
        S2: Into<String>,
        S3: Into<String>,
        S4: Into<String>,
        S5: Into<String>,
    {
        Ok(Self {
            partition: validate_partition(partition)?,
            principal_type: PrincipalType::User(IAMUserDetails::new(account_id, path, name, user_id)?),
        })
    }

    pub fn service<S1, S2>(
        partition: S1,
        service_name: S2,
    ) -> Result<Self, PrincipalError>
    where
        S1: Into<String>,
        S2: Into<String>,
    {
        Ok(Self {
            partition: validate_partition(partition)?,
            principal_type: PrincipalType::Service(service_name.into()),
        })
    }
}

impl Display for Principal {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match &self.principal_type {
            PrincipalType::AssumedRole(ref d) => write!(
                f,
                "arn:{}:sts::{}:assumed-role{}{}/{}",
                self.partition, d.account_id, d.path, d.name, d.session_name
            ),
            PrincipalType::Group(ref d) => {
                write!(f, "arn:{}:iam::{}:group{}{}", self.partition, d.account_id, d.path, d.name)
            }
            PrincipalType::Role(ref d) => {
                write!(f, "arn:{}:iam::{}:role{}{}", self.partition, d.account_id, d.path, d.name)
            }
            PrincipalType::User(ref d) => {
                write!(f, "arn:{}:iam::{}:user{}{}", self.partition, d.account_id, d.path, d.name)
            }
            PrincipalType::Service(s) => write!(f, "arn:{}:iam::amazonaws:service/{}", self.partition, s),
        }
    }
}

/// Principal type
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub enum PrincipalType {
    AssumedRole(IAMAssumedRoleDetails),
    Role(IAMRoleDetails),
    Group(IAMGroupDetails),
    User(IAMUserDetails),
    Service(String),
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct IAMAssumedRoleDetails {
    /// The account id (12 digits for AWS).
    pub account_id: String,

    /// Path, starting with a "/".
    pub path: String,

    /// Name of the pricnipal, case-insensitive.
    pub name: String,

    /// Session name for the assumed role.
    pub session_name: String,
}

impl IAMAssumedRoleDetails {
    pub fn new<S1, S2, S3, S4>(account_id: S1, path: S2, name: S3, session_name: S4) -> Result<Self, PrincipalError>
    where
        S1: Into<String>,
        S2: Into<String>,
        S3: Into<String>,
        S4: Into<String>,
    {
        Ok(Self {
            account_id: validate_account_id(account_id)?,
            path: validate_path(path)?,
            name: validate_name(name, 64)?,
            session_name: session_name.into(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct IAMGroupDetails {
    /// The account id (12 digits for AWS).
    pub account_id: String,

    /// Path, starting with a "/".
    pub path: String,

    /// Name of the pricnipal, case-insensitive.
    pub name: String,

    /// Unique group id -- will change if principal name is reissued.
    pub group_id: String,
}

impl IAMGroupDetails {
    pub fn new<S1, S2, S3, S4>(account_id: S1, path: S2, name: S3, group_id: S4) -> Result<Self, PrincipalError>
    where
        S1: Into<String>,
        S2: Into<String>,
        S3: Into<String>,
        S4: Into<String>,
    {
        Ok(Self {
            account_id: validate_account_id(account_id)?,
            path: validate_path(path)?,
            name: validate_name(name, 128)?,
            group_id: group_id.into(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct IAMRoleDetails {
    /// The account id (12 digits for AWS).
    pub account_id: String,

    /// Path, starting with a "/".
    pub path: String,

    /// Name of the pricnipal, case-insensitive.
    pub name: String,

    /// Unique role id -- will change if principal name is reissued.
    pub role_id: String,
}

impl IAMRoleDetails {
    pub fn new<S1, S2, S3, S4>(account_id: S1, path: S2, name: S3, role_id: S4) -> Result<Self, PrincipalError>
    where
        S1: Into<String>,
        S2: Into<String>,
        S3: Into<String>,
        S4: Into<String>,
    {
        Ok(Self {
            account_id: validate_account_id(account_id)?,
            path: validate_path(path)?,
            name: validate_name(name, 64)?,
            role_id: role_id.into(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct IAMUserDetails {
    /// The account id (12 digits for AWS).
    pub account_id: String,

    /// Path, starting with a "/".
    pub path: String,

    /// Name of the pricnipal, case-insensitive.
    pub name: String,

    /// Unique user id -- will change if principal name is reissued.
    pub user_id: String,
}

impl IAMUserDetails {
    pub fn new<S1, S2, S3, S4>(account_id: S1, path: S2, name: S3, user_id: S4) -> Result<Self, PrincipalError>
    where
        S1: Into<String>,
        S2: Into<String>,
        S3: Into<String>,
        S4: Into<String>,
    {
        Ok(Self {
            account_id: validate_account_id(account_id)?,
            path: validate_path(path)?,
            name: validate_name(name, 64)?,
            user_id: user_id.into(),
        })
    }
}

fn validate_partition<S: Into<String>>(partition: S) -> Result<String, PrincipalError> {
    let partition = partition.into();
    let p_bytes = partition.as_bytes();
    let p_len = p_bytes.len();

    if p_len == 0 || p_len > 32 {
        return Err(PrincipalError::InvalidPartition);
    }

    let mut last_was_dash = false;
    for (i, c) in p_bytes.iter().enumerate() {
        if *c == b'-' {
            if i == 0 || i == p_len - 1 || last_was_dash {
                return Err(PrincipalError::InvalidPartition);
            }

            last_was_dash = true;
        } else if !c.is_ascii_alphanumeric() {
            return Err(PrincipalError::InvalidPartition);
        } else {
            last_was_dash = false;
        }
    }

    drop(p_bytes);
    Ok(partition)
}

fn validate_account_id<S: Into<String>>(account_id: S) -> Result<String, PrincipalError> {
    let account_id = account_id.into();
    let a_bytes = account_id.as_bytes();

    if a_bytes.len() != 12 {
        return Err(PrincipalError::InvalidAccountId);
    }

    for c in a_bytes.iter() {
        if !c.is_ascii_digit() {
            return Err(PrincipalError::InvalidAccountId);
        }
    }

    drop(a_bytes);
    Ok(account_id)
}

fn validate_path<S: Into<String>>(path: S) -> Result<String, PrincipalError> {
    let path = path.into();
    let p_bytes = path.as_bytes();
    let p_len = p_bytes.len();

    if p_len == 0 || p_len > 512 {
        return Err(PrincipalError::InvalidPath);
    }

    // Must begin and end with a slash
    if p_bytes[0] != b'/' || p_bytes[p_len - 1] != b'/' {
        return Err(PrincipalError::InvalidPath);
    }

    // Check that all characters fall in the fange u+0021 - u+007e
    for c in p_bytes {
        if *c < 0x21 || *c > 0x7e {
            return Err(PrincipalError::InvalidPath);
        }
    }

    drop(p_bytes);
    Ok(path)
}

fn validate_name<S: Into<String>>(name: S, max_length: usize) -> Result<String, PrincipalError> {
    let name = name.into();
    let n_bytes = name.as_bytes();
    let n_len = n_bytes.len();

    if n_len == 0 || n_len > max_length {
        return Err(PrincipalError::InvalidName);
    }

    // Check that all characters are alphanumeric or , - . = @ _
    for c in n_bytes {
        if !(c.is_ascii_alphanumeric()
            || *c == b','
            || *c == b'-'
            || *c == b'.'
            || *c == b'='
            || *c == b'@'
            || *c == b'_')
        {
            return Err(PrincipalError::InvalidName);
        }
    }

    drop(n_bytes);
    Ok(name)
}
