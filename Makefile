REGISTRY?=ghcr.io/alexsjones
IMAGE_NAME?=kflow-daemon
IMAGE_TAG?=latest
IMAGE?=$(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)
DOCKERFILE?=Dockerfile.daemon
CONNTRACK_PATH?=/proc/net/nf_conntrack

.PHONY: build docker-build docker-push k8s-apply k8s-delete clean

# Build the Rust binary (release)
build:
	cargo build --release --bin daemon

# Build docker image (will call build first to ensure binary is ready)
docker-build: build
	docker build -t $(IMAGE) -f $(DOCKERFILE) .

# Push image to registry. Provide REGISTRY variable (e.g. REGISTRY=ghcr.io/you)
docker-push:
	@if [ "$(REGISTRY)" = "" ]; then \
		echo "Set REGISTRY to push (e.g. REGISTRY=ghcr.io/you)"; exit 1; \
	fi
	docker push $(IMAGE)

# Apply the DaemonSet to the cluster; this replaces the image placeholder with $(IMAGE)

k8s-apply:
	@sed "s|REPLACE_IMAGE|$(IMAGE)|g; s|REPLACE_CONNTRACK|$(CONNTRACK_PATH)|g" k8s/daemonset.yaml | kubectl apply -f -

k8s-delete:
	@sed "s|REPLACE_IMAGE|$(IMAGE)|g; s|REPLACE_CONNTRACK|$(CONNTRACK_PATH)|g" k8s/daemonset.yaml | kubectl delete -f -

clean:
	cargo clean
