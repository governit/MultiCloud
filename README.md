# MultiCloud
Automatic Configuration of Multi-Cloud Services 

## Risk Quantification

This project containst the datasets and results for quantifying risk on configured services by using machine learning techniques.

## Multi-Cloud Product Line

This project contains a multi-cloud motivation scenario. This model is not meant to be used in real-world cases. The structure and content of this project is described as follows:

- **libs:** it contains the dependency of Choco v3.3.3, a Java constraint programming solver used to find optimal configurations.
- **metamodel:** it contains the CoCo Ecore metamodel (i.e. CoCoMM) for representing extended multi-product lines, and the CoCo DSL Ecore metamodel (i.e. Test7).
- **model:** two versions of the motivation case are presented. Artifacts of version 2 correpond to:
  - *coco-multi-cloud-v2.xmi:* XMI CoCo model of the initial multi-cloud context. 
  - *dsl-coco-multi-cloud-v2.test7:* Xtext CoCo DSL with the specification of user preferences of the initial multi-cloud context.
  - *coco-multi-cloud-config-v2.txt:* selected configuration that responds to domain constraints and user preferences of the initial multi-cloud context. Each feature has a boolean value (1: selected, 0: deselected).
  - *coco-multi-cloud-v2.properties:* multi-cloud intial data in a properties format.
  - *coco-multi-cloud-adapted-v2.xmi:* XMI CoCo model of the adapted multi-cloud context. 
  - *dsl-coco-multi-cloud-adapted-v2.test7:* Xtext CoCo DSL with the specification of user preferences of the adapted multi-cloud context.
  - *coco-multi-cloud-config-adapted-v2.txt:* selected configuration that responds to domain constraints and user preferences of the initial multi-cloud context. Each feature has a boolean value (1: selected, 0: deselected).
  - *coco-multi-cloud-adapted-v2.properties:* multi-cloud adapted data in a properties format.
- **src/scenario:** it contains generated code that maps from the multi-cloud model to the Choco model. *MultiCloud.java* and *MultiCloudAdapted.java* are executed to obtain a set of configurations that conform to domain constraints and user preferences, in the initial and adapted context.
