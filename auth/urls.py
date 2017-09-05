from rest_framework import routers

from auth import views

router = routers.DefaultRouter()
router.register(r'users', views.UserProfileViewSet, base_name='users')

urlpatterns = router.urls