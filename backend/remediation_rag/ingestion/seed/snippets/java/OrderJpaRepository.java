package com.example.orders;

import java.time.Instant;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

/**
 * Approved pattern: Spring Data JPA.
 *
 * House rules:
 * - Prefer derived query methods (findBy...), which are always parameterized.
 * - @Query uses JPQL with named :params bound via @Param.
 * - EntityManager.createQuery / createNativeQuery must use setParameter, never concatenation.
 */
public interface OrderJpaRepository extends JpaRepository<Order, Long> {

    List<Order> findByCustomerIdAndStatus(Long customerId, OrderStatus status);

    @Query("SELECT o FROM Order o WHERE o.customer.email = :email AND o.createdAt >= :since")
    List<Order> findRecentByCustomerEmail(
            @Param("email") String email, @Param("since") Instant since);

    @Query(
            value = "SELECT * FROM orders WHERE status = :status AND total_cents > :minTotal",
            nativeQuery = true)
    List<Order> findLargeOrders(
            @Param("status") String status, @Param("minTotal") long minTotalCents);
}
