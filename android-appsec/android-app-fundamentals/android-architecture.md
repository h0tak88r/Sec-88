# Android Architecture

Android OS implements many security components and has many considerations for its various layers; the following diagram summarizes the Android security architecture on ARM with TrustZone support:

![](https://static.packt-cdn.com/products/9781785287817/graphics/B04179\_04\_03.jpg)

### Layers of Modern Android Application Architecture

#### UI Layer

Puts data from the application on the screen. The UI Layer is typically made up of two more compact parts (UI = UI Elements + UI State).

#### Domain Layer

This layer is optional; not all applications, particularly basic ones, require a domain layer to manage reusable business logic or are too complex to be contained entirely within the data layer. The business logic of an application specifies the creation, storage, and modification of data.

#### Data Layer

Data sources and repositories are the two elements that make up the data layer, which controls the majority of the application’s business logic.

### Android Framework

* **Definition:** The Android Framework provides essential classes for building Android applications. It manages the user interface, application resources, and acts as an abstraction layer for hardware access.
* **Services Offered:**
  * Telephony service
  * Location services
  * Notification management
  * NFC service
  * View system, etc.
* **APIs Access:**
  * Entire Android OS features are accessible to developers through Java-written APIs.
* **Crucial Components:**
  1. **View System:** Facilitates the creation of graphic elements for app interaction.
  2. **Activity Manager:** Manages app entry points and UI components called activities.
  3. **Location Manager:** Utilizes GPS for precise user location.
  4. **Telephony Manager:** Integrates hardware and software elements for telephony services.
  5. **Resource Manager:** Provides access to non-code resources like layout files and graphics.
  6. **Content Provider:** Facilitates standardized data sharing between apps.
  7. **Notification Manager:** Handles informing users about application events.

### Android System Architecture

1. **Linux Kernel:**
   * Foundation of Android architecture.
   * Manages drivers, resources, security, memory, and multitasking.
2. **Android Runtime:**
   * Includes Dalvik Virtual Machine (DVM) for executing Android applications.
   * Converts Java byte code to `.dex` files for optimization.
3. **Libraries:**
   * Native libraries offering instructions for handling various data types.
   * Includes Java-based and C/C++ core libraries for graphics, SSL, SQLite, media, etc.
4. **Application Framework:**
   * Provides high-level services, APIs, and an Android Hardware Abstraction Layer (HAL).
   * Interfaces between the application layer and native libraries.
   * Services like Resource Manager, Notification Manager, Package Manager.....
5. **Applications:**
   * Top layer containing installed third-party and native Android apps.
   * Includes all user-installed programs, games, settings, etc.

## Application Journey

1. Code -> Compile -> DEX Format
2. DEX -> Build -> APK
3. APK -> Signature -> Signed APK&#x20;
4. Signed APK -> Google Play -> User Install

