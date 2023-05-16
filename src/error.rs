#[derive(Debug)]
pub enum Error {
    FaltaParametro(String),
    ArchivoInvalido(String),
    CantInvalidaNodos(String),
    MerkleTreeNotGenerated(String),
    // NoNodesAvailable
    // NoInternetConnection
    // etc
}
