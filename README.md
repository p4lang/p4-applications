P4 Applications Repository 
============================

This repo hosts deliverables from P4 Applications WG.
- WG meeting materials and minutes 
- Application specifications
- Packet formats expressed in P4
- Reference source code
- Test cases

Working Group Charter
----------------------
The Applications WG charter is available [here](https://github.com/p4lang/p4-applications/blob/master/docs/charter.pdf).

Meeting Minutes
---------------------
WG meeting minutes prior to Oct 2019 are posted to the [Wiki](https://github.com/p4lang/p4-applications/wiki) of thie repo.

Meeting minutes from Oct 2019 and after are directly distributed to the mailing list. You can find them in the archive
[https://lists.p4.org/list/p4-apps.lists.p4.org](https://lists.p4.org/list/p4-apps.lists.p4.org)

Directory Structure
------------------
* _docs_ - PDF files of all specs and charter
* _meeting_slides_ - slides used for the WG discussions  
* _telemetry_ - telemetry application
  - _telemetry/specs_ - source files for telemetry specs
* _Makefile_ - Makefile to compile charter.mdk
* _charter.mdk_ - source file for charter

Mailing list
-------------------
- To subscribe, visit
  [https://lists.p4.org/list/p4-apps.lists.p4.org](https://lists.p4.org/list/p4-apps.lists.p4.org)
- To post a message to all list members, send an email to <p4-apps@lists.p4.org>

To create a pull request
------------------------
1. First create a fork of this repo
1. Modify the source file of the spec you want to change. e.g., telemetry/specs/INT.mdk.
1. Push your changes to your fork
1. Create a pull request from your fork against the original repo, master branch
1. Please assign WG chairs as reviewers
