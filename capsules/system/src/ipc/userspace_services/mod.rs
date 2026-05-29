/*! Services in userspace.

This module provides a framework for running service-level functionality as applications in userspace,
offering a middle-ground between adding or modifying a capsule and bundling code within a single application.
The service application is available for use by the entire platform and is separately deployable.
Since the code implementing the service exists in an application,
changing the service's operation does not require an OS-level modification and update.
More specifically,
decoupling particular operations from application
while simultaneously avoiding OS-level implementation enables:
sharing common, necessary function;
isolating less stable code from an application;
writing modular, swappable components;
etc.

# Architecture

Support for userspace services builds on capsules and HILs.
Central to this support is the **userspace service registry** ([`Registry`]),
which tracks and mediates communication with userspace service applications.
Userspace services register with the registry by sending it a syscall,
thereafter communicating exclusively with the registry to fulfill its function.
Coordinated syscalls and upcalls between the registry and userspace service application,
*usercalls*,
define the operations the userspace service exposes.

In order to use the userspace service,
clients interact with the **service interface** which implements the HIL defining its function.
Acting as a mapper between HIL functions and usercalls,
the service interface invokes userspace service operations through the userspace service registry.
The two communicate through the [`UserspaceServiceClient`] and [`UserspaceServiceAccess`] traits
to send data between the consumer of the userspace service and the userspace service.

By implementing HIL traits,
existing capsules can consume a service interface and,
in turn,
offer the functionality of the userspace service to other userspace applications transparently through their syscall driver definition.
The userspace service application can be transparently updated and swapped out without changing the OS.

The following diagram gives a visual overview of the architecture and communication flow:
```text
        +--------------------+              +-------------------+
        | Client Application |              | Userspace Service |
        +--------------------+              +-------------------+
                  |                             |        ^ |
                  | Syscalls           register |        | | usercalls and returns
                  |                     syscall |        | | (upcalls and syscalls)
                  v                             v        | v
   =================================================================
     KERNEL       |                             |        ^ |
                  v                             |        | |
        +--------------------+                  |        | |
        |      Capsule       |                  |        | |
        +--------------------+                  |        | |
                  |                             |        | |
                  v                             |        | |
             +---------+                        |        | |
             |HIL trait|                        |        | |
        +----+---------+------------------+     |        | |
        |        Service Interface        |     |        | |
        +---------------------------------+     |        | |
           | |UserspaceServiceClient trait|     |        | |
           | +----------------------------+     |        | |
usercall() |                            ^       |        | |
           v            usercall_done() |       |        | |
        +----------------------------+  |       |        | |
        |UserspaceServiceAccess trait|  |       v        | v
        +----------------------------------------------------------+
        |                          Registry                        |
        +----------------------------------------------------------+
```

# Communication

Usercalls and their returns combine
syscalls,
upcalls,
and buffer `allow`s
to move data between the userspace service application and its client.
To invoke a userspace service operation,
the registry sends an upcall to the userspace service application,
placing arguments as upcall arguments
or in the service application's read-write `allow` buffers.
The first argument of the upcall is an **operation ID** identifying the operation the client is requesting the userspace service run.
The userspace service application returns the result of the operation with a syscall to the registry,
placing return data as syscall arguments
or in its read-only `allow` buffers.

To support more than a single userspace service application,
and to disambiguate interactions of one userspace service from another,
the registry addresses each userspace service with a unique **role ID**.
The role ID identifies the userspace service's function at a high level,
for example,
a role providing cryptographic hashing.
When registering,
the userspace service provides the registry with its role ID.
No two services may fulfill the same role.
 */

pub mod comm;
pub mod data;
pub mod registry;
pub mod role;

pub use comm::{
    ReturnValueReader,
    UserspaceServiceAccess,
    UserspaceServiceClient,
    UsercallArguments,
};

pub use data::{
    Bytes,
    Deserialize,
    Serialize,
};

pub use registry::{
    DRIVER_NUM,
    Registry,
};

pub use role::Role;
