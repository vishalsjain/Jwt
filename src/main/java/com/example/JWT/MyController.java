package com.example.JWT;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MyController {

    @GetMapping("/user")
public void getUser(){
        System.out.println("get USercalled");

}

}
