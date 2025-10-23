# Stegano DCT

DCT(이산 코사인 변환) 워터마킹 기술을 사용하여 이미지에 텍스트 메시지를 삽입하고 추출하는 커맨드 라인 도구입니다.

StegoDCT는 이산 코사인 변환 계수를 조작하여 JPEG 및 PNG 이미지의 주파수 영역 내에 은닉된 텍스트 워터마크를 삽입하여 인지할 수 없도록 저장됩니다.

## 주요기능

-DCT 변환을 통해 품질 저하 없이 텍스트 워터마크를 십입하여 메시지를 은닉
-JPEG 및 PNG 이미지 모두 동작 -은닉 데이터를 통해 워터마크 탐지 및 변조 방지

## 설치

StegoDCT는 Python 3.6+ 및 다음 라이브러리를 필요로합니다:

- NumPy
- OpenCV (cv2)
- Pillow (PIL)

## 사용법

이 스크립트는 메시지 삽입을 위한 encrypt와 추출을 위한 decrypt 두 가지 주요 명령을 제공합니다

### 메시지 삽입

```bash
python StegoDCT.py encrypt -i input_image.jpg -m "Your secret message" -o output_image -f png
```

Parameters:

- `-i, --input`: 입력 이미지 경로 (JPG, PNG 및 기타 일반적인 형식 지원)
- `-m, --message`: 이미지에 삽입할 텍스트 메시지
- `-o, --output`: 출력 이미지 경로
- `-f, --format`: 출력 형식: `png` 또는 `jpeg`
- `--max-size`: 최대 파일 크기(바이트 단위, 선택 사항)

### 메시지 추출

```bash
python StegoDCT.py decrypt -i output_image.png
```

매게변수:

-i, --input: 숨겨진 메시지가 포함된 이미지 경로

### 주의 사항

메시지가 삽입된 후 이미지가 수정, 압축 등 변환 처리된 경우 추출이 불완전하거나 손상된 결과가 나올 수 있습니다.

## 작동원리

StegoDCT는 이미지의 이산 코사인 변환(DCT)의 중간 주파수 계수에 메시지 비트를 삽입하여 작동합니다.

1. 이미지를 8x8 픽셀 블록으로 나눕니다.
2. 각 블록에 DCT를 적용합니다.
3. 메시지 비트를 인코딩하기 위해 특정 DCT 계수를 수정합니다.
4. 역 DCT를 적용하여 이미지를 복원합니다

DCT 주파수 기반 워터마크는 사람의 눈에 감지할 수 없지만 알고리즘에 의해 감지될 수 있습니다.

## Limitations

- The maximum message length depends on the image size (larger images can store more text)
- Heavy compression or significant image modification may corrupt the hidden message
- The technique is most effective with PNG output (lossless compression)
