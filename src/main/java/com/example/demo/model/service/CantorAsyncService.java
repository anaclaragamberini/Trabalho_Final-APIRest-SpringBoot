package com.example.demo.model.service;

import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
public class CantorAsyncService {

    @Async
    public void processarCantor(String nome) {
        try {
            Thread.sleep(3000);
            System.out.println("Processamento assíncrono do cantor: " + nome);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }
}