@id("example-vm-commands")
permit(
    principal == Dekopon::Principal::"example-caller",
    action in [Dekopon::Action::"vm.exec", Dekopon::Action::"vm.job.get", Dekopon::Action::"vm.artifact.read"],
    resource == Dekopon::Provider::"vm"
) when { context has agent && context.agent == "example-agent" };

@id("example-vm-token")
permit(
    principal == Dekopon::Principal::"example-caller",
    action == Dekopon::Action::"secret.use",
    resource == Dekopon::Secret::"drn:com.xrl:secret:prod:vm/token"
) when {
    context.provider == "vm" && context.sink == "httpBearer"
    && ["vm.exec", "vm.job.get", "vm.artifact.read"].contains(context.capability)
};
