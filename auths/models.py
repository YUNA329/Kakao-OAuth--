from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser

class UserManager(BaseUserManager):

  # nickname 과 description 을 가지는 유저 모델 생성
  def create_user(self, nickname, description):
    if not nickname:
      raise ValueError('must have user nickname')
    user = self.model( nickname=nickname )
    user.description = description
    user.save()
    return user

  def create_superuser(self, nickname, description, ):
    if not nickname:
      raise ValueError('must have user nickname')
    user = self.model( nickname=nickname )
    user.description = description
    user.is_admin = True
    user.save()
    return user

class User(AbstractBaseUser):
  nickname = models.CharField(max_length=30, unique=True, null=False)
  description = models.TextField()
  is_active = models.BooleanField(default=True)
  is_admin = models.BooleanField(default=False)

  objects = UserManager()

  # unique identifier 설정
  USERNAME_FIELD = 'nickname'
  # 필수로 받고 싶은 값 - USERNAME_FIELD 값과 패스워드는 항상 기본으로 요구하므로 여기에 추가로 명시 필요 없음
  # 슈퍼유저를 생성할 때 적용 됨!
  REQUIRED_FIELDS = ['description']

  @property
  def is_staff(self):
    return self.is_admin
