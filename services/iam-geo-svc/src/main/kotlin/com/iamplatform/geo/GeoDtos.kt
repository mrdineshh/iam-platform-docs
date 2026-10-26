package com.iamplatform.geo

data class GeoRangeEntry(
    val cidr: String,
    val country: String,
    val region: String,
    val city: String,
    val note: String? = null,
)

data class GeoResolution(
    val ip: String,
    val resolved: Boolean,
    val country: String? = null,
    val region: String? = null,
    val city: String? = null,
)
