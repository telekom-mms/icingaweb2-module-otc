Open Telekom Cloud (T-Cloud Public) Importer for Icinga Web 2
=============================================================

An Icinga Director Import Source module that fetches resources from
**Open Telekom Cloud / T-Cloud Public** via the OpenStack-compatible APIs.

Resources and their columns are discovered automatically from the service
catalog and the API responses – nothing is hardcoded.

Requirements
------------
* PHP >= 7.3 with `ext-curl` and `ext-json`
* Icinga Web 2 >= 2.4.1
* Icinga Director >= 1.3.0

Installation
------------
Clone the repository into a folder called `otc` inside one of your Icinga
Web 2 module paths, then enable it:

```
git clone https://… /usr/share/icingaweb2/modules/otc
icingacli module enable otc
```

Configuration
-------------
In Icinga Director go to **Automation → Import Source → Add** and select
**OTC** as the source type.

| Field | Required | Description |
|-------|----------|-------------|
| IAM URL | ✔ | Keystone v3 base URL, e.g. `https://iam.eu-de.otc.t-systems.com` |
| Username | ✔ | OTC IAM user name |
| Password | ✔ | OTC IAM password |
| Domain Name | ✔ | Account domain, e.g. `OTC0000123456` |
| Project / Region | ✔ | Project name, usually equals the region, e.g. `eu-de` |
| Region Filter | | Narrow endpoint lookup to a specific region |
| Service Type | ✔ | OpenStack service catalog type (see table below) |
| Resource Path | ✔ | Path within the service endpoint (see table below) |
| HTTP Proxy | | Optional proxy URL |
| Connect / Request Timeout | | cURL timeouts in seconds; `0` = no limit |

Common service types and resource paths
---------------------------------------

| What to monitor | Service Type | Resource Path |
|-----------------|--------------|---------------|
| Virtual machines (ECS) | `compute` | `/servers/detail` |
| Networks (VPC) | `network` | `/networks` |
| Subnets | `network` | `/subnets` |
| Routers | `network` | `/routers` |
| Load balancers (ELB) | `network` | `/lbaas/loadbalancers` |
| Block volumes (EVS) | `volumev2` | `/volumes/detail` |
| DNS zones | `dns` | `/zones` |
| RDS instances | `rdsv3` | `/instances` |
| DCS instances | `dcs` | `/instances` |
| NAT gateways | `nat` | `/nat_gateways` |
| WAF instances | `waf` | `/premium/instance` |

> **Tip:** The available service types are printed in the error message when
> you enter a wrong type – that list comes directly from your project's
> service catalog, so it always reflects what is actually provisioned.

How it works
------------
1. `run.php` registers the `director/ImportSource` hook.
2. `ImportSource.php` presents the settings form and calls `OtcClient`.
3. `OtcClient` authenticates via **Keystone v3** (`POST /v3/auth/tokens`).
   The resulting `X-Subject-Token` and the **service catalog** are cached
   for the lifetime of the token.
4. The public endpoint for the requested service type is looked up in the
   catalog – no URLs are hardcoded.
5. Resources are fetched with `GET {endpoint}{resource_path}`.
   **Pagination** (OpenStack `*_links[rel=next]`) is followed automatically
   until all pages are retrieved.
6. The resource list is detected automatically by finding the largest
   non-empty indexed array in the response body.
7. Column names are extracted from the top-level keys of the first resource.
   Use Icinga Director **Import Modifiers** to access nested fields.

A practical import + sync walkthrough is available at
https://icinga.com/docs/icinga-director/latest/doc/70-Import-and-Sync/

Credits
-------
Inspired by [icingaweb2-module-azgraph](../icingaweb2-module-azgraph) and
[icingaweb2-module-azure](https://github.com/credativ/icingaweb2-module-azure),
both published under the MIT licence.
