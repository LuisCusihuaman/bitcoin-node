#[derive(Debug)]
pub enum Error {
    FaltaParametro(String),
    ArchivoInvalido(String),
    // Posibles errores
    // NoNodesAvailable
    // NoInternetConnection
    // etc
}
