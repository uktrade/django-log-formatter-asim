import os


def _get_container_id():
    """
    The dockerId (container Id) is available via the metadata endpoint.

    However, it looks like it is embedded in the metadata URL e.g.:
    ECS_CONTAINER_METADATA_URI=http://169.254.170.2/v3/709d1c10779d47b2a84db9eef2ebd041-0265927825
    See: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-metadata-endpoint-v4-response.html
    """

    try:
        return os.environ["ECS_CONTAINER_METADATA_URI"].split("/")[-1]
    except (KeyError, IndexError):
        return ""
