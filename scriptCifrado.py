# -*- coding: utf-8 -*-
"""
IMPLEMENTACIÓN DEMO-CLI DEL MODELO CRIPTOGRÁFICO POLIMÓRFICO PARA IoT
Basado en el paper: "Cryptography model to secure IoT device endpoints, 
based on polymorphic cipher OTP"

Autores: Carlos Bran, Douglas Flores, Carlos Hernández
Universidad Don Bosco, El Salvador

"""

import socket
import secrets
import random
import struct
import hashlib
from typing import List, Tuple
from enum import Enum
import time
import argparse # Módulo para manejar argumentos de la línea de comandos

# Define los tipos de mensajes que los nodos pueden intercambiar, según el paper.
class MessageType(Enum):
    """Tipos de mensajes según el paper."""
    FCM = 0  # First Contact Message: Para iniciar la comunicación y sincronizar claves.
    RM = 1   # Regular Message: Un mensaje con datos de aplicación, ya cifrado.
    KUM = 2  # Key Update Message: Para solicitar una nueva tabla de claves (no implementado en demo).
    LCM = 3  # Last Contact Message: Para terminar la comunicación (no implementado en demo).

class PolymorphicCipher:
    """
    Motor criptográfico que implementa el cifrado polimórfico.
    Gestiona la generación de claves, el cifrado y descifrado de mensajes.
    """
    
    def __init__(self, node_id: int = None):
        """Inicializa el cifrador con un ID de nodo único."""
        self.node_id = node_id or random.randint(1, 0xFFFF)
        self.key_table: List[bytes] = []
        self.key_index = 0
        self.last_psn = 0
        
        # Parámetros P, Q, S que se intercambian en el primer contacto (FCM).
        self.P = 0
        self.Q = 0  
        self.S = 0
        
    def generate_prime(self, bits: int = 16) -> int:
        """Genera un número primo de 'bits' para los parámetros P y Q."""
        while True:
            num = random.getrandbits(bits)
            if num > 1 and self._is_prime(num):
                return num
    
    def _is_prime(self, n: int) -> bool:
        """Función de ayuda para verificar si un número es primo (test básico)."""
        if n < 2: return False
        for i in range(2, int(n**0.5) + 1):
            if n % i == 0: return False
        return True
    
    def generate_shared_secret(self, own_params: tuple, peer_params: tuple) -> bytes:
        """
        Crea un 'secreto compartido' usando los parámetros (P, Q, S) de ambos nodos.
        Este método es determinístico: ambos nodos generarán el mismo secreto.
        Utiliza SHA-256 para garantizar seguridad y consistencia.
        """
        own_P, own_Q, own_S = own_params
        peer_P, peer_Q, peer_S = peer_params
        
        # Empaqueta los parámetros en bytes.
        data1 = struct.pack('>III', own_P, own_Q, own_S)
        data2 = struct.pack('>III', peer_P, peer_Q, peer_S)
        
        # Ordena los datos para que la entrada del hash sea idéntica en ambos nodos.
        combined_data = data1 + data2 if data1 < data2 else data2 + data1
        
        # Genera el secreto compartido usando un hash criptográfico.
        return hashlib.sha256(combined_data).digest()
    
    def generate_key_table(self, shared_secret: bytes, N: int = 100) -> None:
        """
        Genera una tabla de N claves de un solo uso (OTP) a partir del secreto compartido.
        Al usar el secreto como semilla, ambos nodos generan la misma secuencia de claves.
        """
        self.key_table = []
        seed_int = int.from_bytes(shared_secret[:8], 'big')
        rng = random.Random(seed_int)
        
        for _ in range(N):
            key_bytes = rng.getrandbits(64).to_bytes(8, 'big')
            self.key_table.append(key_bytes)
        
        self.key_index = 0
    
    def get_next_key(self) -> bytes:
        """Obtiene la siguiente clave disponible de la tabla y la "descarta"."""
        if self.key_index >= len(self.key_table):
            raise Exception("Tabla de claves agotada. Se necesita un Key Update Message (KUM).")
        
        key = self.key_table[self.key_index]
        self.key_index += 1
        return key
    
    def _get_reversible_functions(self) -> List[Tuple]:
        """
        Define el conjunto de operaciones de cifrado/descifrado.
        Cada tupla contiene: (Función de Cifrado, Función de Descifrado, Nombre para mostrar).
        """
        return [
            (lambda d, k: bytes(b ^ k[i % len(k)] for i, b in enumerate(d)),
             lambda d, k: bytes(b ^ k[i % len(k)] for i, b in enumerate(d)),
             "XOR Cifrado/Descifrado"),
            
            (lambda d, k: bytes((b + k[i % len(k)]) & 0xFF for i, b in enumerate(d)),
             lambda d, k: bytes((b - k[i % len(k)]) & 0xFF for i, b in enumerate(d)),
             "Suma/Resta Modular"),
            
            (lambda d, k: bytes(((b << 2) | (b >> 6)) & 0xFF for i, b in enumerate(d)),
             lambda d, k: bytes(((b >> 2) | (b << 6)) & 0xFF for i, b in enumerate(d)),
             "Rotación de Bits Izq/Der")
        ]
    
    def _extract_psn(self, message: bytes) -> int:
        """
        Extrae el Polymorphic Sequence Nibble (PSN) de forma determinística desde el mensaje.
        """
        if not message: return 0
        msg_hash = hashlib.md5(message).digest()[0]
        psn = (msg_hash + self.last_psn) & 0x0F
        return psn
    
    def encrypt_message(self, plaintext: bytes) -> Tuple[bytes, int]:
        """Cifra un mensaje usando una clave y una función seleccionada por el PSN."""
        key = self.get_next_key()
        current_psn = self._extract_psn(plaintext)
        functions = self._get_reversible_functions()
        func_index = current_psn % len(functions)
        encrypt_func, _, func_name = functions[func_index]
        
        print(f"[{self.node_id} | Encrypt] PSN calculado a partir del mensaje: {current_psn}")
        print(f"[{self.node_id} | Encrypt] Función seleccionada por PSN ({current_psn} % {len(functions)} = {func_index}): '{func_name}'")
        print(f"[{self.node_id} | Encrypt] Usando Clave #{self.key_index} -> {key.hex()}")

        ciphertext = encrypt_func(plaintext, key)
        self.last_psn = current_psn
        return ciphertext, current_psn
    
    def decrypt_message(self, ciphertext: bytes, psn: int) -> bytes:
        """Descifra un mensaje usando la misma clave y PSN que el emisor."""
        key = self.get_next_key()
        functions = self._get_reversible_functions()
        func_index = psn % len(functions)
        _, decrypt_func, func_name = functions[func_index]

        print(f"[{self.node_id} | Decrypt] PSN recibido en cabecera: {psn}")
        print(f"[{self.node_id} | Decrypt] Función seleccionada por PSN ({psn} % {len(functions)} = {func_index}): '{func_name}'")
        print(f"[{self.node_id} | Decrypt] Usando Clave #{self.key_index} -> {key.hex()}")

        plaintext = decrypt_func(ciphertext, key)
        self.last_psn = psn
        return plaintext

class IoTMessage:
    """Clase para empaquetar y desempaquetar los mensajes para su transmisión por red."""
    def __init__(self, node_id: int, msg_type: MessageType, psn: int, payload: bytes):
        self.node_id, self.msg_type, self.psn, self.payload = node_id, msg_type, psn, payload
    
    def pack(self) -> bytes:
        """Convierte la estructura del mensaje a una secuencia de bytes."""
        header = struct.pack('>HBB', self.node_id, self.msg_type.value, self.psn)
        return header + self.payload
    
    @classmethod
    def unpack(cls, data: bytes) -> 'IoTMessage':
        """Crea un objeto IoTMessage a partir de una secuencia de bytes recibida."""
        if len(data) < 4: raise ValueError("Mensaje demasiado corto.")
        node_id, msg_type_val, psn = struct.unpack('>HBB', data[:4])
        return cls(node_id, MessageType(msg_type_val), psn, data[4:])

class IoTEndpoint:
    """Representa un nodo IoT. Gestiona el estado de la conexión y el protocolo."""
    def __init__(self, node_id: int = None):
        self.cipher = PolymorphicCipher(node_id)
        self.is_synchronized = False
        
    def create_fcm_message(self) -> bytes:
        """Crea el Mensaje de Primer Contacto (FCM) con los parámetros P, Q, S."""
        self.cipher.P = self.cipher.generate_prime(16)
        self.cipher.Q = self.cipher.generate_prime(16) 
        self.cipher.S = random.randint(1, 0xFFFFFFFF)
        payload = struct.pack('>III', self.cipher.P, self.cipher.Q, self.cipher.S)
        return IoTMessage(self.cipher.node_id, MessageType.FCM, 0, payload).pack()
    
    def process_fcm_and_generate_keys(self, peer_msg: IoTMessage) -> None:
        """Procesa un FCM, genera el secreto compartido y la tabla de claves."""
        peer_P, peer_Q, peer_S = struct.unpack('>III', peer_msg.payload[:12])
        own_params, peer_params = (self.cipher.P, self.cipher.Q, self.cipher.S), (peer_P, peer_Q, peer_S)
        
        print(f"[{self.cipher.node_id}] Procesando FCM del peer ({peer_msg.node_id}). Parámetros recibidos: P={peer_P}, Q={peer_Q}")
        print(f"[{self.cipher.node_id}] hashlib.sha256( (P,Q,S propios) + (P,Q,S del peer) ) ...")
        
        shared_secret = self.cipher.generate_shared_secret(own_params, peer_params)
        print(f"[{self.cipher.node_id}] Secreto compartido generado: {shared_secret.hex()}")
        
        self.cipher.generate_key_table(shared_secret, 100)
        print(f"[{self.cipher.node_id}] Tabla de 100 claves generada a partir del secreto. Mostrando las primeras 5:")
        for i, key in enumerate(self.cipher.key_table[:5]):
            print(f"    Clave #{i+1}: {key.hex()}")
        
        self.is_synchronized = True
        print(f"[{self.cipher.node_id}] ¡SINCRONIZACIÓN COMPLETA! Listo para comunicación cifrada.")

    def encrypt_regular_message(self, plaintext: str) -> bytes:
        """Cifra y empaqueta un mensaje de texto para ser enviado como Mensaje Regular (RM)."""
        if not self.is_synchronized: raise Exception("No sincronizado.")
        
        print(f"\n[{self.cipher.node_id}] --- Proceso de Cifrado ---")
        print(f"[{self.cipher.node_id}] Mensaje original: '{plaintext}'")
        
        payload_bytes = plaintext.encode('utf-8')
        ciphertext, psn = self.cipher.encrypt_message(payload_bytes)
        
        print(f"[{self.cipher.node_id}] Texto cifrado (payload): {ciphertext.hex()}")
        return IoTMessage(self.cipher.node_id, MessageType.RM, psn, ciphertext).pack()
    
    def decrypt_regular_message(self, data: bytes) -> str:
        """Desempaqueta y descifra un Mensaje Regular (RM) recibido."""
        msg = IoTMessage.unpack(data)
        if msg.msg_type != MessageType.RM: raise ValueError("Se esperaba un RM.")
        
        print(f"\n[{self.cipher.node_id}] --- Proceso de Descifrado ---")
        print(f"[{self.cipher.node_id}] Mensaje recibido del nodo {msg.node_id}. Payload: {msg.payload.hex()}")
        
        plaintext_bytes = self.cipher.decrypt_message(msg.payload, msg.psn)
        decrypted_text = plaintext_bytes.decode('utf-8')
        
        print(f"[{self.cipher.node_id}] Mensaje descifrado: '{decrypted_text}'")
        return decrypted_text

# ===================== PROGRAMAS PRINCIPALES (DEMO) =====================

def sender_main(message_to_send: str):
    """Programa que actúa como cliente/emisor."""
    endpoint = IoTEndpoint()
    HOST, PORT = "127.0.0.1", 65432
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print(f"[SENDER {endpoint.cipher.node_id}] Conectado al receiver.")
        
        print("\n" + "="*25 + " FASE 1: SINCRONIZACIÓN " + "="*25)
        fcm_data = endpoint.create_fcm_message()
        print(f"[SENDER {endpoint.cipher.node_id}] Parámetros generados: P={endpoint.cipher.P}, Q={endpoint.cipher.Q}, S={endpoint.cipher.S}")
        print(f"[SENDER {endpoint.cipher.node_id}] Enviando FCM...")
        s.sendall(fcm_data)
        
        peer_fcm_data = s.recv(1024)
        endpoint.process_fcm_and_generate_keys(IoTMessage.unpack(peer_fcm_data))
        
        print("\n" + "="*23 + " FASE 2: ENVÍO DE DATOS " + "="*24)
        time.sleep(1)
        encrypted_data = endpoint.encrypt_regular_message(message_to_send)
        print(f"[SENDER {endpoint.cipher.node_id}] Enviando mensaje cifrado...")
        s.sendall(encrypted_data)

        print("\n" + "="*20 + " FASE 3: ESPERANDO RESPUESTA " + "="*21)
        encrypted_response = s.recv(1024)
        if encrypted_response: endpoint.decrypt_regular_message(encrypted_response)
        
        print(f"\n[SENDER {endpoint.cipher.node_id}] Comunicación finalizada. Claves restantes: {len(endpoint.cipher.key_table) - endpoint.cipher.key_index}")

def receiver_main():
    """Programa que actúa como servidor/receptor."""
    endpoint = IoTEndpoint()
    HOST, PORT = "127.0.0.1", 65432
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"[RECEIVER {endpoint.cipher.node_id}] Servidor iniciado. Esperando conexión...")
        conn, addr = s.accept()
        with conn:
            print(f"[RECEIVER {endpoint.cipher.node_id}] Conexión aceptada de {addr}")
            
            print("\n" + "="*25 + " FASE 1: SINCRONIZACIÓN " + "="*25)
            fcm_data = conn.recv(1024)
            
            our_fcm = endpoint.create_fcm_message()
            print(f"[RECEIVER {endpoint.cipher.node_id}] Parámetros generados: P={endpoint.cipher.P}, Q={endpoint.cipher.Q}, S={endpoint.cipher.S}")
            print(f"[RECEIVER {endpoint.cipher.node_id}] Enviando FCM de respuesta...")
            conn.sendall(our_fcm)
            
            endpoint.process_fcm_and_generate_keys(IoTMessage.unpack(fcm_data))

            print("\n" + "="*20 + " FASE 2: RECEPCIÓN DE DATOS " + "="*21)
            encrypted_data = conn.recv(1024)
            if encrypted_data:
                endpoint.decrypt_regular_message(encrypted_data)
                
                print("\n" + "="*22 + " FASE 3: ENVIANDO RESPUESTA " + "="*23)
                time.sleep(1)
                response = "RECEIVER confirma: mensaje OK!"
                encrypted_response = endpoint.encrypt_regular_message(response)
                print(f"[RECEIVER {endpoint.cipher.node_id}] Enviando respuesta cifrada...")
                conn.sendall(encrypted_response)

            print(f"\n[RECEIVER {endpoint.cipher.node_id}] Comunicación finalizada. Claves restantes: {len(endpoint.cipher.key_table) - endpoint.cipher.key_index}")

if __name__ == "__main__":
    # Configura el parser para aceptar argumentos desde la línea de comandos
    parser = argparse.ArgumentParser(
        description="Demo del Cifrador Polimórfico para IoT.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument("role", 
                        choices=['sender', 'receiver'], 
                        help="Define el rol del nodo: 'sender' (cliente) o 'receiver' (servidor).")
    
    parser.add_argument("-m", "--message", 
                        type=str, 
                        default="¡Hola Mundo con Cifrado Polimórfico!",
                        help="El mensaje que el 'sender' enviará cifrado.\nEjemplo: python %(prog)s sender -m \"Mi mensaje secreto\"")

    args = parser.parse_args()
    
    if args.role == 'sender':
        sender_main(args.message)
    else:
        receiver_main()

