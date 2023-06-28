# Technical Information
| Property               | Value    |
| :--------------------: | :------: |
| Security Strength      | 256 bits |
| Hash                   | SHA-256  |
| Prediction Resistance  | Yes      |
| Additional Input       | No       |
| Personalisation String | No       |

* SHA-256 has been implemented from scratch, because I wanted this package to have no dependencies.
* It is assumed that `/dev/urandom` always provides sufficient entropy for seeding.
