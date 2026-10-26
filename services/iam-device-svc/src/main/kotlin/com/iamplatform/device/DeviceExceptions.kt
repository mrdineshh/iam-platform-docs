package com.iamplatform.device

import java.util.UUID

class UserNotFoundException(tenantId: UUID, userId: UUID) :
    RuntimeException("No user $userId under tenant $tenantId")

class DeviceNotFoundException(tenantId: UUID, userId: UUID) :
    RuntimeException("No device enrolled for user $userId under tenant $tenantId")

class NoPushCapableDeviceException(tenantId: UUID, userId: UUID) :
    RuntimeException("No push-capable device enrolled for user $userId under tenant $tenantId")

class ChallengeNotFoundException(challengeId: UUID) :
    RuntimeException("No pending push challenge $challengeId")

class ChallengeAlreadyResolvedException(challengeId: UUID) :
    RuntimeException("Push challenge $challengeId was already resolved")
