import numpy as np
import cv2
from PIL import Image
import io
import os
import sys
from typing import Tuple, Union, Optional


class StegoDCT:
    """이산 코사인(DCT) 변환을 이용한 스테가노그래피"""
    
    # DCT 처리를 위한 상수
    BLOCK_SIZE = 8  # DCT 블록 크기
    QUANTIZATION_FACTOR = 25  # 삽입 강도 조절
    THRESHOLD = 15  # 탐지 임계값
    
    def __init__(self, max_file_size: Optional[int] = None):
        """
         StegoDCT 객체를 초기화
        
        max_file_size: 최대 파일 크기 (바이트 단위, 선택 사항)
        """
        self.max_file_size = max_file_size
    
    def _string_to_bits(self, message: str) -> list:
        """문자열을 비트 리스트로 변환"""
        # 메시지를 바이트로 변환한 후 비트로 변환
        byte_array = message.encode('utf-8')
        bits = []
        for byte in byte_array:
            for i in range(7, -1, -1):  # 최상위 비트(MSB)부터
                bits.append((byte >> i) & 1)
        
        # 종료 시퀀스(16개의 1) 추가
        bits.extend([1] * 16)
        return bits
    
    def _bits_to_string(self, bits: list) -> str:
        """비트 리스트를 문자열로 변환합니다."""
        # 비트를 바이트로 그룹화
        bytes_data = bytearray()
        for i in range(0, len(bits), 8):
            if i + 8 > len(bits):  # 끝에 불완전한 바이트가 있는 경우
                break
            
            byte = 0
            for j in range(8):
                byte = (byte << 1) | bits[i + j]
            bytes_data.append(byte)
        
                # 바이트를 문자열로 디코딩

        try:
            return bytes_data.decode('utf-8')
        except UnicodeDecodeError:
            # 마지막 유효한 UTF-8 시퀀스까지만 반환하여 잠재적인 디코딩 오류 처리
            for i in range(len(bytes_data), 0, -1):
                try:
                    return bytes_data[:i].decode('utf-8')
                except UnicodeDecodeError:
                    continue
            return ""
    
    def _prepare_image(self, image_path: str) -> np.ndarray:
        """DCT 처리를 위해 이미지를 로드하고 준비"""
        # 파일 존재 여부 확인
        if not os.path.exists(image_path):
            raise FileNotFoundError(f"이미지 파일을 찾을 수 없습니다: {image_path}")
            
        # max_file_size가 지정된 경우 파일 크기 확인
        if self.max_file_size is not None:
            file_size = os.path.getsize(image_path)
            if file_size > self.max_file_size:
                raise ValueError(f"입력 파일 크기 ({file_size} bytes)가 최대 허용 크기 ({self.max_file_size} bytes)를 초과합니다.")
        
        # 이미지 읽기
        img = cv2.imread(image_path, cv2.IMREAD_COLOR)
        if img is None:
            # OpenCV가 실패하면 PIL 사용 시도 (다양한 형식에 대한 지원)
            try:
                pil_img = Image.open(image_path)
                img = np.array(pil_img.convert('RGB'))
                img = cv2.cvtColor(img, cv2.COLOR_RGB2BGR)
            except Exception as e:
                raise ValueError(f"이미지를 열지 못했습니다: {e}")
        
        # 이미지가 유효한지 확인
        if img.size == 0 or img.shape[0] < self.BLOCK_SIZE or img.shape[1] < self.BLOCK_SIZE:
            raise ValueError(f"이미지가 너무 작습니다. 최소 크기: {self.BLOCK_SIZE}x{self.BLOCK_SIZE}")
            
        return img
    
    def _save_image(self, img: np.ndarray, output_path: str, format_type: str) -> None:
        """"지정된 형식으로 이미지를 저장합니다."""
        format_type = format_type.lower()
        
        # # output_path가 올바른 확장자를 갖도록 함
        base_path, _ = os.path.splitext(output_path)
        if format_type == 'png':
            output_path = f"{base_path}.png"
            cv2.imwrite(output_path, img, [cv2.IMWRITE_PNG_COMPRESSION, 9])
        elif format_type == 'jpeg' or format_type == 'jpg':
            output_path = f"{base_path}.jpg"
            cv2.imwrite(output_path, img, [cv2.IMWRITE_JPEG_QUALITY, 95])
        else:
            raise ValueError(f"지원되지 않는 출력 형식: {format_type}")
            
        # 파일이 생성되었는지 확인
        if not os.path.exists(output_path):
            raise IOError(f"{output_path}에 이미지를 저장하지 못했습니다.")

    def _embed_bit_in_dct_block(self, block: np.ndarray, bit: int) -> np.ndarray:
        """입력된 비트를 DCT 계수 블록에 삽입합니다."""
        # DCT를 위해 블록을 float32로 변환
        block_float = np.float32(block)
        
        # 블록에 DCT 적용
        dct_block = cv2.dct(block_float)

        # 비트에 따라 중간 주파수 계수(4,4)를 수정
        # 이 위치는 견고성과 인지 가능성 사이의 균형을 맞춤
        if bit == 1:
            # 계수가 양수이고 임계값보다 큰지 확인
            if dct_block[4, 4] < self.THRESHOLD:
                dct_block[4, 4] = self.THRESHOLD + self.QUANTIZATION_FACTOR
        else:
            # 계수가 음수이거나 임계값보다 작은지 확인
            if dct_block[4, 4] > -self.THRESHOLD:
                dct_block[4, 4] = -self.THRESHOLD - self.QUANTIZATION_FACTOR

        # 역 DCT 적용
        idct_block = cv2.idct(dct_block)
        
        # 값을 유효한 범위로 클리핑
        return np.clip(idct_block, 0, 255).astype(np.uint8)
    
    def _extract_bit_from_dct_block(self, block: np.ndarray) -> int:
        """DCT 계수 블록에서 단일 비트를 추출합니다."""
        # DCT를 위해 블록을 float32로 변환
        block_float = np.float32(block)
        
        # 블록에 DCT 적용
        dct_block = cv2.dct(block_float)

        # 중간 주파수 계수(4,4)에 따라 비트 추출
        return 1 if dct_block[4, 4] > 0 else 0
    
    def encrypt(self, image_path: str, message: str, output_path: str, output_format: str) -> None:
        """
        DCT를 사용하여 이미지에 메시지를 삽입합니다.

        """
        img = self._prepare_image(image_path)
        height, width, channels = img.shape

        # 메시지를 비트 시퀀스로 변환
        bits = self._string_to_bits(message)

        # 삽입할 수 있는 최대 비트 수 계산
        # 전체 블록만 고려
        blocks_height = height // self.BLOCK_SIZE
        blocks_width = width // self.BLOCK_SIZE
        max_bits = blocks_height * blocks_width * channels
        
        if len(bits) > max_bits:
            raise ValueError(f"텍스트 최대 길이 초과. 최대 비트: {max_bits}, 필요: {len(bits)}")
        
        bit_index = 0
        modified_img = np.copy(img)
        
        # 각 채널을 개별적으로 처리
        for channel in range(3):  # RGB 채널
            if bit_index >= len(bits):
                break
                
            channel_data = modified_img[:, :, channel]
            
            # 8x8 블록 처리
            for y in range(0, blocks_height * self.BLOCK_SIZE, self.BLOCK_SIZE):
                for x in range(0, blocks_width * self.BLOCK_SIZE, self.BLOCK_SIZE):
                    if bit_index >= len(bits):
                        break
                        
                    # 현재 블록 가져오기
                    block = channel_data[y:y+self.BLOCK_SIZE, x:x+self.BLOCK_SIZE]
                    
                    # 비트 삽입
                    modified_block = self._embed_bit_in_dct_block(block, bits[bit_index])

                    # 수정된 블록으로 이미지를 업데이트
                    modified_img[y:y+self.BLOCK_SIZE, x:x+self.BLOCK_SIZE, channel] = modified_block
                    
                    bit_index += 1
                
                if bit_index >= len(bits):
                    break
        
        # 수정된 이미지 저장
        self._save_image(modified_img, output_path, output_format)
    
    def decrypt(self, image_path: str) -> str:
        """
        DCT를 사용하여 이미지에서 메시지를 추출합니다.
        """
        img = self._prepare_image(image_path)
        height, width, channels = img.shape
        
        # 완전한 블록만 가져오기
        blocks_height = height // self.BLOCK_SIZE
        blocks_width = width // self.BLOCK_SIZE
        
        extracted_bits = []
        consecutive_ones = 0
        
        # 각 채널을 개별적으로 처리
        for channel in range(3):  # RGB 채널
            channel_data = img[:, :, channel]

            # 8x8 블록 처리
            for y in range(0, blocks_height * self.BLOCK_SIZE, self.BLOCK_SIZE):
                for x in range(0, blocks_width * self.BLOCK_SIZE, self.BLOCK_SIZE):
                    # 종료 시퀀스(16개의 연속된 1) 확인
                    if consecutive_ones >= 16:
                        break

                    # 현재 블록 가져오기
                    block = channel_data[y:y+self.BLOCK_SIZE, x:x+self.BLOCK_SIZE]

                    # 비트 추출
                    bit = self._extract_bit_from_dct_block(block)
                    extracted_bits.append(bit)

                    # 종료 시퀀스 확인
                    if bit == 1:
                        consecutive_ones += 1
                    else:
                        consecutive_ones = 0
                
                if consecutive_ones >= 16:
                    break
            
            if consecutive_ones >= 16:
                break
        
        # 종료 시퀀스 제거
        if consecutive_ones >= 16:
            extracted_bits = extracted_bits[:-consecutive_ones]
        else:
            print("error 발생 : 메시지가 불완전하거나 손상되었을 수 있습니다.")
        
        # 비트를 문자열로 변환
        return self._bits_to_string(extracted_bits)
    
    def calculate_max_message_length(self, image_path: str) -> int:
      
        img = self._prepare_image(image_path)
        height, width, channels = img.shape
        
        # 삽입할 수 있는 최대 비트 수 계산
        blocks_height = height // self.BLOCK_SIZE
        blocks_width = width // self.BLOCK_SIZE
        max_bits = blocks_height * blocks_width * channels

        # 종료 시퀀스(16비트) 고려
        max_bits -= 16

        # 최대 UTF-8 문자 수로 변환(대략, 1바이트당 1문자 가정)
        # 최악의 경우, UTF-8 문자는 최대 4바이트까지 가능
        max_chars = max_bits // 8  # 8비트 = 1바이트
        
        return max_chars


def interactive_mode():
    print("\n=== dct 워터마킹 ===")
    print("은닉 워터마크를 삽입하거나 추출하는 프로그램입니다.\n")
    
    # 1단계: 작업 선택
    print("1단계: 작업 선택")
    print("1. 암호화 (워터마킹할 메시지 삽입)")
    print("2. 복호화 (이미지에서 숨겨진 메시지 추출)")
    
    while True:
        try:
            choice = input("\nEnter your choice (1 or 2): ").strip()
            if choice == '1':
                encrypt_interactive()
                break
            elif choice == '2':
                decrypt_interactive()
                break
            else:
                print("Invalid choice. Please enter 1 or 2.")
        except Exception as e:
            print(f"Error: {e}")


def encrypt_interactive():
    steganographer = StegoDCT()

    # 2단계: 입력 이미지 선택
    print("\n2단계: 입력 이미지 선택 (PNG 또는 JPEG)")
    
    while True:
        try:
            image_path = input("여기에 이미지 파일을 드래그 앤 드롭하거나 경로를 입력하세요: ").strip()
            image_path = image_path.strip('"\'')
            
            if not os.path.exists(image_path):
                print(f"파일을 찾을 수 없습니다: {image_path}")
                print("다시 시도해 주세요:")
                continue
            
                # 최대 메시지 길이 계산
            max_length = steganographer.calculate_max_message_length(image_path)
            print(f"\n최대 메시지 길이: {max_length}자")
            break
        except Exception as e:
            print(f"Error: {e}")
            print("다시 시도해 주세요:")

    # 3단계: 암호화할 메시지 입력
    print("\n3단계: 이미지에 숨길 메시지 입력")
    print(f"(최대 {max_length}자)")

    while True:
        try:
            message = input("메시지: ")
            if not message:
                print("메시지는 비워둘 수 없습니다. 다시 시도해 주세요:")
                continue
                
            if len(message) > max_length:
                print(f"메시지가 너무 깁니다. 최대 길이는 {max_length}자입니다.")
                print("다시 시도해 주세요:")
                continue
                
            break
        except Exception as e:
            print(f"Error: {e}")
            print("다시 시도해 주세요:")

    # 4단계: 출력 형식 선택
    print("\n4단계: 출력 형식 선택")
    print("1. PNG (더 나은 품질, 권장)")
    print("2. JPEG (더 작은 파일 크기)")
    
    output_format = "png"
    while True:
        try:
            format_choice = input("출력 형식을 선택하세요 (1 또는 2): ").strip()
            if format_choice == '1':
                output_format = "png"
                break
            elif format_choice == '2':
                output_format = "jpeg"
                break
            else:
                print("유효하지 않은 선택입니다. 1 또는 2를 입력하세요.")
        except Exception as e:
            print(f"Error: {e}")
    
    # 5단계: 출력 경로 가져오기
    print("\n5단계: 출력 파일 이름 입력 (확장자 제외)")
    
    while True:
        try:
            output_name = input("출력 파일 이름: ").strip()
            if not output_name:
                base = os.path.basename(image_path)
                name_without_ext = os.path.splitext(base)[0]
                output_name = f"{name_without_ext}_secret"
                print(f"기본 파일 이름 사용: {output_name}")
            
            # 형식에 따라 확장자 추가
            ext = ".png" if output_format == "png" else ".jpg"
            output_path = output_name
            
            # 진행하기 전에 확인
            print(f"\n생성 준비 완료: {output_path}{ext}")
            confirm = input("진행하시겠습니까? (y/n): ").lower()
            if confirm != 'y':
                print("작업이 취소되었습니다. 다시 시도해 주세요:")
                continue
                
            break
        except Exception as e:
            print(f"Error: {e}")
            print("다시 시도해 주세요:")

    # 암호화 처리
    print("\n워터마킹 중...")
    try:
        steganographer.encrypt(image_path, message, output_path, output_format)
        print(f"\n성공! 메시지가 {output_path}{ext}에 숨겨졌습니다.")
    except Exception as e:
        print(f"암호화 중 오류 발생: {e}")


def decrypt_interactive():
    steganographer = StegoDCT()
    
    # 2단계: 입력 이미지 가져오기
    print("\n2단계: 숨겨진 메시지가 있는 이미지 선택")

    while True:
        try:
            image_path = input("여기에 이미지 파일을 드래그 앤 드롭하거나 경로를 입력하세요: ").strip()
            image_path = image_path.strip('"\'')
            
            if not os.path.exists(image_path):
                print(f"파일을 찾을 수 없습니다: {image_path}")
                print("다시 시도해 주세요:")
                continue
                
            break
        except Exception as e:
            print(f"Error: {e}")
            print("다시 시도해 주세요:")

    # 복호화 처리
    print("\n워터마크 추출 중...")
    try:
        message = steganographer.decrypt(image_path)
        print("\n=== 추출된 메시지 ===")
        print(message)
        print("========================")
    except Exception as e:
        print(f"복호화 중 오류 발생: {e}")


def main():
    try:
        interactive_mode()
    except KeyboardInterrupt:
        print("\n작업이 취소되었습니다.")
        sys.exit(0)
    except Exception as e:
        print(f"예기치 않은 오류 발생: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
    
