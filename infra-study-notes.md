Hypervisors

Hyperjacking

Containers

Escaping and privilege escalation techniques

Site isolation

Network connections from VMs / containers

Side-channel attacks

    Attack based on information gained from the implementation of a computer system, rather than weaknesses

Beyondcorp
    
    Trusting the host but not the network.

Kubernetes Security

    BUILD PHASE SECURITY
    
    Use minimal base images - Avoid using images with OS package managers or shells 
    Don’t add unnecessary components - Remove debugging tools from containers in production
    Use up-to-date images only - Ensure images are up to date and utilizing the latest versions of their components
    Use an image scanner to identify known vulnerabilities
    Integrate security into your CI/CD pipeline
    Label non-fixable vulnerabilities
    Implement defense-in-depth

    DEPLOY PHASE SECURITY
    
    Use namespaces to isolate sensitive workloads - 
        Namespaces are a key isolation boundary for Kubernetes resources
        They provide a reference for network policies, access control restrictions, and other important security controls
        Separating workloads into namespaces can help contain attacks and limit the impact of mistakes or destructive actions by authorized users
    Use Kubernetes network policies to control traffic between pods and clusters
        By default, Kubernetes allows every pod to contact every other pod. 
        Network segmentation policies will prevent lateral movement

    Prevent overly permissive access to secrets
    Assess the privileges used by containers        
        Do not run application processes as root
        Do not allow privilege escalation
        Use a read-only root filesystem
        Use the default (masked) /proc filesystem mount
        Do not use the host network or process space
        Drop unused and unnecessary Linux capabilities
        Use SELinux options for more fine-grained process controls
        Give each application its own Kubernetes Service Account
        Do not mount the service account credentials in a container if it does not need to access the Kubernetes API

    Assess image provenance, including registries
        Using images from known registries/ones allow lists
    Extend your image scanning to deploy phase
        Images that haven’t been scanned recently might contain vulnerabilities
    Use labels and annotations appropriately
        Makes it easier to alert the responsible team for triaging security issues
    Enable Kubernetes role-based access control (RBAC)
        Controlling authorization to access a cluster’s Kubernetes API server, both for users and service accounts in the cluster
    
    RUNTIME PHASE SECURITY
    
    Leverage contextual information in Kubernetes
        Use the build and deploy time information to evaluate observed versus expected activity during runtime in order to detect suspicious activity
    Extend vulnerability scanning to running deployments
        Monitor running deployments for newly discovered vulnerabilities in addition to scanning for vulnerabilities that exist in container images.
    Use Kubernetes built-in controls when available to tighten security
        Configure the security context for pods to limit their capabilities
    Monitor network traffic to limit unnecessary or insecure communication
    Leverage process of allow lists
    Compare and analyze different runtime activity in pods of the same deployments
    If breached, scale suspicious pods to zero
        Use Kubernetes native controls to contain a successful breach by automatically instructing Kubernetes to scale suspicious pods to zero or kill then restart instances of breached applications
    
    INFRA SECURITY
    
    Update your Kubernetes to the latest version whenever possible
    Securely configure the Kubernetes API server
        Disable unauthenticated/anonymous access
        Using TLS encryption for connections between the kubelets and the API server
    Secure etcd
        etcd is a key-value store (a CNCF project) used by Kubernetes for data access
        etcd is considered the source of truth for Kubernetes, and you can read data from and write into it as needed
    Secure the kubelet
        Misconfiguring kubelet exposes you to backdoor access
        Disable anonymous access
        
    OPERATIONAL SECURITY
    
    Use Kubernetes-native security controls to reduce operational risk
        Leverage the native controls built into Kubernetes whenever available in order to enforce security policies
