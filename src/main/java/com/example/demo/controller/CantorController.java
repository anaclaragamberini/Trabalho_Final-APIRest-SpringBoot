package com.example.demo.controller;

import com.example.demo.model.entity.Cantor;
import com.example.demo.model.service.CantorService;
import com.example.demo.model.service.CantorAsyncService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/cantores")
public class CantorController {

    @Autowired
    private CantorService cantorService;

    @Autowired
    private CantorAsyncService asyncService;

    @PostMapping("/novo")
    public ResponseEntity<Boolean> criarCantor(@RequestBody Cantor cantor) {
        cantorService.criarCantor(cantor);

        asyncService.processarCantor(cantor.getNome());

        return ResponseEntity.status(201).body(true);
    }

    @GetMapping
    public ResponseEntity<List<Cantor>> getCantores() {
        List<Cantor> cantores = cantorService.getCantores();
        return ResponseEntity.status(200).body(cantores);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Boolean> deletarCantorPorId(@PathVariable("id") Long id) {

        try {
            cantorService.deletarCantorPorId(id);
            return ResponseEntity.ok(true);
        } catch (Exception e) {
            return ResponseEntity.status(404).body(false);
        }
    }

    @PutMapping("/{id}")
    public ResponseEntity<Boolean> atualizarCantor(
            @PathVariable Long id,
            @RequestBody Cantor dadosNovos) {

        try {
            cantorService.atualizarCantor(id, dadosNovos);
            return ResponseEntity.ok(true);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(false);
        }
    }
}
