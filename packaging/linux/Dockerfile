FROM public.ecr.aws/amazonlinux/amazonlinux:2023

# Install development tools, gcc, and cmake (needed by aws-lc-sys cmake builder)
RUN dnf groupinstall -y "Development Tools" \
    && dnf install -y gcc cmake \
    && dnf clean all

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="~/.cargo/bin:${PATH}"

WORKDIR /nfm

ENTRYPOINT ["/nfm/packaging/linux/create_rpm.sh"]
