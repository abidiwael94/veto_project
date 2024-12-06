package com.example.spring_security_jwt.models;

import jakarta.persistence.*;

@Entity
@Table(name = "roles")
public class Role {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Enumerated(EnumType.STRING)
    @Column(length = 20)
    private com.example.spring_security_jwt.models.ERole name;

    public Role() {

    }

    public Role(com.example.spring_security_jwt.models.ERole name) {
        this.name = name;
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public com.example.spring_security_jwt.models.ERole getName() {
        return name;
    }

    public void setName(com.example.spring_security_jwt.models.ERole name) {
        this.name = name;
    }
}