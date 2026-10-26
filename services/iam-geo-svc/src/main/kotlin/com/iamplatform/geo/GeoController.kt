package com.iamplatform.geo

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/v1")
class GeoController(
    private val geoLookupService: GeoLookupService,
) {

    @GetMapping("/resolve")
    fun resolve(@RequestParam ip: String): GeoResolution = geoLookupService.resolve(ip)
}
