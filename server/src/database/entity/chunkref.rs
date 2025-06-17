pub type ChunkRefModel = Model;

#[derive(Debug, Clone, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "chunkref")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,

    #[sea_orm(indexed)]
    pub nar_id: i64,

    pub seq: i32,

    #[sea_orm(indexed)]
    pub chunk_id: Option<i64>,

    #[sea_orm(indexed)]
    pub chunk_hash: String,
    pub compression: String,
}
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::chunk::Entity",
        from = "Column::ChunkId",
        to = "super::chunk::Column::Id"
    )]
    Chunk,
    #[sea_orm(
        belongs_to = "super::nar::Entity",
        from = "Column::NarId",
        to = "super::nar::Column::Id"
    )]
    Nar,
}
impl Related<super::chunk::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Chunk.def()
    }
}
impl Related<super::nar::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Nar.def()
    }
}
impl ActiveModelBehavior for ActiveModel {}
