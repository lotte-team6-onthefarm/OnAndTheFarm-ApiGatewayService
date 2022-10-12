package com.team6.onandthefarmapigateway.feignclient;

import com.team6.onandthefarmapigateway.vo.SellerResponse;
import com.team6.onandthefarmapigateway.vo.UserResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@FeignClient(name = "member-service")
public interface MemberServiceClient {

    @GetMapping("/api/user/member-service/user/{user-no}")
    UserResponse findByUserId(@PathVariable("user-no") Long userId);

    @GetMapping("/api/seller/member-service/seller/{seller-no}")
    SellerResponse findBySellerId(@PathVariable("seller-no") Long sellerId);

}
