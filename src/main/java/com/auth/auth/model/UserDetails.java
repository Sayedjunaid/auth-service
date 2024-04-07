package com.auth.auth.model;


import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserDetails {

    @NotNull(message = "name is mandatory")
    @JsonProperty(value = "name", required = true)
    private String name;

    @Email(
            message = "email should be valid",
            regexp = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$")
    @JsonProperty(value = "email", required = true)
    private String email;


    @NotNull(message = "password is mandatory")
    @JsonProperty(value = "password", required = true)
    private String password;


}
