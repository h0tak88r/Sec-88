# Android Security Model

### 1. Linux Security Models (DAC - Discretionary Access Control)

**DAC (Discretionary Access Control)** is a security model where each system object (files, processes, etc.) has an owner, and the owner has discretion over who is granted access to the object. The access control decisions are at the discretion of the object's owner. In the context of Android, this model is implemented in the Linux kernel, forming the foundation of Android's security.

<figure><img src="../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>DAC Linex Security</p></figcaption></figure>

### 2. SELinux Security Model (MAC - Mandatory Access Control)

**MAC (Mandatory Access Control)** is a security model where access permissions are set by a central authority, typically the operating system or a security policy. **SELinux (Security-Enhanced Linux)** is an implementation of MAC on the Linux kernel, providing an additional layer of security on top of DAC.

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>SELinux for every file</p></figcaption></figure>

* **Principle: Default Denied:**
  * In SELinux, the default principle is to deny access unless explicitly allowed. This ensures a more secure environment by minimizing the potential for unintended access.
* **SELinux History:**
  * Versions 4.2.2 and below didn't support SELinux.
  * Version 4.3 supported SELinux but with the status "Permissive."
  * Versions 5.0 and up support SELinux with the status "Enforce."
* **SELinux States:**
  * **Enforce:** Enforcing SELinux policies, denying any actions that violate the set policies.
  * **Permissive:** Logging violations but not enforcing them, allowing for policy testing without blocking actions.
  * **Disabled:** SELinux is turned off, and no security policies are applied.
* **SELinux Types:**
  * **Default:** Basic SELinux security model.
  * **MLS (Multi-Level Security):** Allows different levels of access to different users.
  * **SRC (Strict/Role-Based Access Control):** Users have roles, and access is defined based on roles.
* **Who Can Set SELinux?:**
  * Identification of entities with the authority to configure SELinux. Typically, system administrators or users with specific privileges or the Android Phone Company Engineers.
* **How to Get SELinux State (Android - Linux):**
  * `getenforce`: Getting the SELinux status.
  * `setenforce 0`: Change the status permanently to permissive.

### Permissions for system apps

Every permission has a protection level (`android:protectionlevel`), which is a combination of one required protection (`PermissionInfo.getProtection()`) and multiple optional protection flags (`PermissionInfo.getProtectionFlags()`).

#### Permission protection level

* [`normal`](https://android.googlesource.com/platform/frameworks/base/+/master/core/java/android/permission/Permissions.md#requesting-a-permission): The permission will be granted to apps requesting it in their manifest.
  * Vibrate, ACCESS\_NETWORK\_STATE
* [`dangerous`](https://android.googlesource.com/platform/frameworks/base/+/master/core/java/android/permission/Permissions.md#runtime-permissions): The permission will be a runtime permission.
  * Gallery, Contacts, Camera, GPS
* [`signature`](https://android.googlesource.com/platform/frameworks/base/+/master/core/java/android/permission/Permissions.md#signature-permissions): The permission will be granted to apps being signed with the same certificate as the app defining the permission. If the permission is a platform permission, it means those apps need to be platform-signed.
* `signatureORsystem` - > (deprecatedin API 23)
* `internal`: This is a no-op protection so that it won't allow granting the permission by itself. However, it will be useful when defining permissions that should only be granted according to its protection flags, e.g. `internal|role` for a role-only permission.\
