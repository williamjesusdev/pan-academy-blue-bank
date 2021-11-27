package com.panacademy.squad7.bluebank.services;

import com.panacademy.squad7.bluebank.domain.models.Account;

import java.util.List;

public interface AccountsService {
    Account create(Account account);

    Account update(Account account, Long id);

    void softDelete(Long id);

    void softBlock(Long id);

    Account findById(Long id);

    List<Account> findAll();

    Account findByAgencyNumberAndAccountNumber(Long agencyNumber, Long accountNumber);
}
