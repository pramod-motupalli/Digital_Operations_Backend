# yourapp/permissions.py
from rest_framework import permissions

class IsOwner(permissions.BasePermission):
    """
    Custom permission to only allow owners of an object to view or edit it.
    """
    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed to any request,
        # so we'll always allow GET, HEAD or OPTIONS requests.
        # (This might be too permissive for listing, handled in queryset)

        # Instance must have an attribute named `owner`.
        # For Tasks, we check workspace.owner
        if isinstance(obj, view.get_queryset().model): # Check if obj is a Workspace
            return obj.owner == request.user
        # If obj is a Task, check obj.workspace.owner
        # This requires the view to be set up to handle Tasks
        # A more robust way is to handle this in the view's get_object or queryset
        return False # Default deny


class IsWorkspaceOwnerOrTaskCreator(permissions.BasePermission):
    """
    Custom permission:
    - For Workspaces: only allow owners to edit.
    - For Tasks: only allow the owner of the parent Workspace to interact.
    """
    def has_permission(self, request, view):
        # Allow authenticated users to access the view
        return request.user and request.user.is_authenticated

    def has_object_permission(self, request, view, obj):
        # Write permissions are only allowed to the owner of the workspace.
        # obj is the instance being accessed (Workspace or Task)
        from .models import Workspace, Task # Local import to avoid circular dependency
        if isinstance(obj, Workspace):
            return obj.owner == request.user
        if isinstance(obj, Task):
            return obj.workspace.owner == request.user
        return False