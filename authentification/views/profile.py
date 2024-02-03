from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from authentification.serializers.serializers import RegisterSerializer, UserProfilesSerializer, UserDetailSerializers
from main_services.expected_fields import check_required_key
from main_services.main import UserRenderers
from main_services.responses import (
    bad_request_response,
    success_response,
    success_deleted_response,
)
from main_services.swaggers import swagger_schema, swagger_extend_schema


@swagger_extend_schema(fields={'first_name', 'last_name', 'username', 'avatar'}, description="Custom User Profile")
@swagger_schema(serializer=UserProfilesSerializer)
class ProfileViews(APIView):
    permission_classes = [IsAuthenticated]
    render_classes = [UserRenderers]

    def get(self, request):
        serializer = UserProfilesSerializer(request.user, context={'request': request} )
        return success_response(serializer.data)

    def put(self, request):
        valid_fields = {'first_name', 'last_name', 'username', 'avatar'}
        unexpected_fields = check_required_key(request, valid_fields)
        if unexpected_fields:
            return bad_request_response(f"Unexpected fields: {', '.join(unexpected_fields)}")

        serializer = UserDetailSerializers(request.user, data=request.data, partial=True,
                                              context={'avatar': request.FILES.get('avatar', None), 'request': request})
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return success_response(serializer.data)
        return bad_request_response(serializer.errors)

    def delete(self, request):
        request.user.delete()
        return success_deleted_response("User deleted")