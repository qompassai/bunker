//! An object in a local cache.
//!
//! It's backed by a NAR in the global cache.

use std::path::PathBuf;
use std::str::FromStr;

use sea_orm::Insert;
use sea_orm::entity::prelude::*;
use sea_orm::sea_query::OnConflict;

use super::Json;
use super::nar::NarModel;
use crate::error::{ServerError, ServerResult};
use crate::narinfo::{Compression, NarInfo};
use bunker::hash::Hash;

pub type ObjectModel = Model;

pub trait InsertExt {
    fn on_conflict_do_update(self) -> Self;
}

#[derive(Debug, Clone, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "object")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    #[sea_orm(indexed)]
    pub cache_id: i64,
    pub nar_id: i64,
    #[sea_orm(column_type = "String(Some(32))", indexed)]
    pub store_path_hash: String,
    pub store_path: String,
    pub references: Json<Vec<String>>,
    pub system: Option<String>,
    pub deriver: Option<String>,
    pub sigs: Json<Vec<String>>,

    pub ca: Option<String>,

    pub created_at: ChronoDateTimeUtc,

    pub last_accessed_at: Option<ChronoDateTimeUtc>,

    pub created_by: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::cache::Entity",
        from = "Column::CacheId",
        to = "super::cache::Column::Id"
    )]
    Cache,

    #[sea_orm(
        belongs_to = "super::nar::Entity",
        from = "Column::NarId",
        to = "super::nar::Column::Id"
    )]
    Nar,
}

impl InsertExt for Insert<ActiveModel> {
    fn on_conflict_do_update(self) -> Self {
        self.on_conflict(
            OnConflict::columns([Column::CacheId, Column::StorePathHash])
                .update_columns([
                    Column::NarId,
                    Column::StorePath,
                    Column::References,
                    Column::System,
                    Column::Deriver,
                    Column::Sigs,
                    Column::Ca,
                    Column::CreatedAt,
                    Column::LastAccessedAt,
                    Column::CreatedBy,
                ])
                .to_owned(),
        )
    }
}

impl Model {
    /// Converts this object to a NarInfo.
    pub fn to_nar_info(&self, nar: &NarModel) -> ServerResult<NarInfo> {
        let nar_size = nar
            .nar_size
            .try_into()
            .map_err(ServerError::database_error)?;

        Ok(NarInfo {
            store_path: PathBuf::from(self.store_path.to_owned()),
            url: format!("nar/{}.nar", self.store_path_hash.as_str()),

            compression: Compression::from_str(&nar.compression)?,
            file_hash: None, // FIXME
            file_size: None, // FIXME
            nar_hash: Hash::from_typed(&nar.nar_hash)?,
            nar_size,
            system: self.system.to_owned(),
            references: self.references.0.to_owned(),
            deriver: self.deriver.to_owned(),
            signature: None,
            ca: self.ca.to_owned(),
        })
    }
}

impl Related<super::cache::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Cache.def()
    }
}

impl Related<super::nar::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Nar.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
