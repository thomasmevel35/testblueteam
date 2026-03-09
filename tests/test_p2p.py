import uuid

from p2p.simulator import InMemoryNetwork


def test_message_propagation_and_anti_loop() -> None:
    net = InMemoryNetwork()
    for node in ["n1", "n2", "n3"]:
        net.add_node(node)

    net.connect("n1", "n2")
    net.connect("n2", "n3")

    msg = {"id": str(uuid.uuid4()), "type": "transaction", "payload": {"x": 1}}
    net.broadcast("n1", msg)

    assert len(net.nodes["n2"].inbox) == 1
    assert len(net.nodes["n3"].inbox) == 1

    net.broadcast("n1", msg)
    assert len(net.nodes["n2"].inbox) == 1
    assert len(net.nodes["n3"].inbox) == 1
