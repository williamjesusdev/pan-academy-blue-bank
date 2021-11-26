package com.panacademy.squad7.bluebank.web.dtos.request;

import lombok.Data;

import javax.validation.constraints.DecimalMin;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Positive;
import java.math.BigDecimal;

@Data
public class DepositRequest {

    @Positive
    @DecimalMin(value = "0.01", message = "the amount value must be greater than 0.01")
    @NotNull(message = "amount must not be null")
    private BigDecimal amount;

}