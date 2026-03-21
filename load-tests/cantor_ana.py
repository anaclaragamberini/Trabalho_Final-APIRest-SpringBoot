from locust import HttpUser, task, between
import random

API_KEY = "sk-ed630b76-ae05-4759-95c8-02302195f96d"

class CantorUser(HttpUser):

    wait_time = between(1, 3)

    @task
    def criar_e_buscar_cantor(self):

        nome = f"Cantor Teste {random.randint(1, 10000)}"

        response = self.client.post(
            "/cantores/novo",
            json={
                "nome": nome,
                "nacionalidade": "Brasil"
            },
            headers={"X-API-Key": API_KEY}
        )

        self.client.get(
            "/cantores",
            headers={"X-API-Key": API_KEY}
        )