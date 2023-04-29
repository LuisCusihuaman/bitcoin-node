use app::net::router::Router;

#[test]
fn test_al_pedir_un_balance_el_router_devuelve_resultado_esperado() {
    // setup
    let mut router = Router::new();
    let respuesta_esperado = "Hola";

    let mut balance;

    // ejecutar
    router.get("/getBalance", &balance);

    // verificar
    let mut resultado_devuleto = Server::new(router).run("127.0.0.1:8989");

    assert_eq!(respuesta_esperado, balance);
}
