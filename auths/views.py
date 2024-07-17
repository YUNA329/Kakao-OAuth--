import os
import requests
import jwt
from django.shortcuts import render
from rest_framework import status

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response

from rest_framework_simplejwt.tokens import RefreshToken

from auths.models import User
from auths.serializers import KakaoLoginRequestSerializer, KakaoRegisterRequestSerializer, UserSerializer

class KakaoAccessTokenException(Exception): pass
class KakaoOIDCException(Exception): pass
class KakaoDataException(Exception): pass

def exchange_kakao_access_token(access_code):
    # access_code : 프론트가 넘겨준 인가 코드
    response = requests.post(
        'https://kauth.kakao.com/oauth/token',
        headers={
            'Content-type': 'application/x-www-form-urlencoded;charset=utf-8',
        },
        data={
            'grant_type': 'authorization_code',
            'client_id': os.environ.get('KAKAO_REST_API_KEY'),
            'redirect_uri': os.environ.get('KAKAO_REDIRECT_URI'),
            'code': access_code,
        },
    )
		# 300번대 이상이면 다른 조치 취해야 함 (400: ?error, 500 : server error, ...)
    if response.status_code >= 300:
        raise KakaoAccessTokenException()
    return response.json()

def extract_kakao_nickname(kakao_data):
		# 응답으로 받은 id_token 값 가져오기
    id_token = kakao_data.get('id_token', None)
    
    if id_token is None: # 없으면 예외 처리
        raise KakaoDataException("Missing ID token")
    
    # JWT 키 가져오기 - 서명 검증에 필요한 키
    jwks_client = jwt.PyJWKClient(os.environ.get('KAKAO_OIDC_URI'))
    signing_key = jwks_client.get_signing_key_from_jwt(id_token)
    # JWT의 알고리즘 가져오기 (JWT 헤더에 포함된 정보) - 서명 검증에 필요
    signing_algol = jwt.get_unverified_header(id_token)['alg']

    try: # id_token=jwt의 페이로드에는 사용자 인증 정보들이 담겨 있음
        payload = jwt.decode( # JWT 디코딩 -> 페이로드 추출
            id_token,
            key=signing_key.key,               # JWT의 서명 검증
            algorithms=[signing_algol],        # |-> 유효한지 확인
            audience=os.environ.get('KAKAO_REST_API_KEY'),
        )
    except jwt.InvalidTokenError:
        raise KakaoOIDCException()
    
    return payload['nickname']


@api_view(['POST'])
@permission_classes([AllowAny])
def kakao_login(request):
    serializer = KakaoLoginRequestSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    data = serializer.validated_data
    
    try:
        # 인가 코드로 토큰 발급 -> 닉네임 추출
        kakao_data = exchange_kakao_access_token(data['access_code'])
        nickname = extract_kakao_nickname(kakao_data)
    # 예외 처리
    except KakaoAccessTokenException:
        return Response({'detail': 'Access token 교환에 실패했습니다.'}, status=401)
    except KakaoDataException:
        return Response({'detail': 'OIDC token 정보를 확인할 수 없습니다.'}, status=401)
    except KakaoOIDCException:
        return Response({'detail': 'OIDC 인증에 실패했습니다.'}, status=401)

    try: # 해당 nickname을 가진 user가 있는지 확인
        user = User.objects.get(nickname=nickname)
    except User.DoesNotExist:
        return Response({'detail': '존재하지 않는 사용자입니다.'}, status=404)

    # user 확인 했으므로 우리 토큰 발행
    refresh = RefreshToken.for_user(user)
    return Response({
        'access_token': str(refresh.access_token),
        'refresh_token': str(refresh)
    })

@api_view(['POST'])
@permission_classes([AllowAny])
def kakao_register(request):
    serializer = KakaoRegisterRequestSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    data = serializer.validated_data

    try:
        # 인가 코드로 토큰 발급 -> 닉네임 추출
        kakao_data = exchange_kakao_access_token(data['access_code'])
        nickname = extract_kakao_nickname(kakao_data)
    # 예외 처리
    except KakaoAccessTokenException:
        return Response({'detail': 'Access token 교환에 실패했습니다.'}, status=401)
    except KakaoDataException:
        return Response({'detail': 'OIDC token 정보를 확인할 수 없습니다.'}, status=401)
    except KakaoOIDCException:
        return Response({'detail': 'OIDC 인증에 실패했습니다.'}, status=401)

    ok = False
    try:
        user = User.objects.get(nickname=nickname)
    except User.DoesNotExist:
        ok = True

    if not ok:
        return Response({'detail': '이미 등록 된 사용자입니다.'}, status=400)

    # 사용자 인증하고 우리의 토큰 발급
    user = User.objects.create_user(nickname=nickname, description=data['description'])
    refresh = RefreshToken.for_user(user)
    return Response({
        'access_token': str(refresh.access_token),
        'refresh_token': str(refresh)
    })

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def verify(request):
    return Response({'datail': 'Token is verified.'}, status=200)

# 각 사용자의 프로필 수정은 본인만 가능
@api_view(['GET', 'PATCH'])
@permission_classes([IsAuthenticated])
def user_detail(request, id):
    try:
        user = User.objects.get(id=id)
    except User.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)

    match request.method:
        case 'GET':
            serializer = UserSerializer(user)
            return Response(serializer.data)
        case 'PATCH':
            # 본인만 수정 가능
            if request.user.id != user.id:
                return Response(status=status.HTTP_403_FORBIDDEN)
            serializer = UserSerializer(user, data=request.data, partial=True)
            if serializer.is_valid(): 
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# 모든 사용자는 다른 사용자들의 프로필을 볼 수 있음
@api_view(['GET'])
@permission_classes([AllowAny])
def user_detail_list(request):
    users = User.objects.all()
    serializer = UserSerializer(users, many=True)
    return Response(serializer.data)