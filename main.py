from filter.filter_calls import detect_full_call_merged
from filter.filter_image import detect_images_by_sni, print_detected_images, group_streams_by_timestamp

from filter.filter_text_message import detect_text_messages
from filter.filter_audio_message import detect_audio_messages
from filter.filter_files import detect_file_messages
from filter.filter_location import detect_location_messages, print_detected_locations
from filter.filter_video import detect_video_messages, print_detected_videos


def main_menu():
    while True:
        print("\n=== WhatsApp Traffic Analyzer ===")
        print("1. Analyze PCAP file")
        print("2. Live capture (to be added!)")
        print("0. Exit")
        choice = input("Choose an option: ").strip()

        if choice == '1':
            file_analysis_menu()
        elif choice == '2':
            print("Live capture is not yet available!")
        elif choice == '0':
            print("Exiting.")
            break
        else:
            print("Invalid option. Try again!")


def file_analysis_menu():
    while True:
        print("\n--- Analyze PCAP File ---")
        print("1. Text message")
        print("2. Audio message")
        print("3. Audio/Video call")
        print("4. Location")
        print("5. Image")
        print("6. Video")
        print("7. File")
        print("0. Back")
        choice = input("Choose the message type to detect: ").strip()

        if choice == '1':
            print("Detecting text messages...")
            # detect_text_messages("files/capture1.pcapng")
            detect_text_messages("files/captura-mesaje-telefon-laptop.pcapng")

            # call your text detection function here
        elif choice == '2':
            print("Detecting audio messages...")
            # detect_audio_messages("files/captura-mesaje-audio-laptop.pcapng")
            # group_audio_streams("files/captura-mesaje-audio-bun-laptop.pcapng")
            detect_audio_messages("files/captura-mesaje-audio-final3.pcapng")
        elif choice == '3':
            print("Detecting audio/video calls...")
            detect_full_call_merged("files/captura-apel-audio-bun.pcapng")
        elif choice == '4':
            print("Detecting location messages...")
            messages = detect_location_messages("files/captura-locatie-bun-laptop.pcapng")
            print_detected_locations(messages)
        elif choice == '5':
            print("Detecting images...")
            results = detect_images_by_sni("files/captura-imagini.pcapng")
            print_detected_images(results)
        elif choice == '6':
            print("Detecting videos...")
            results = detect_video_messages("files/captura-2video.pcapng")
            print_detected_videos(results)
        elif choice == '7':
            print("Detecting files...")
            detect_file_messages("files/captura-fisiere-pdf-laptop.pcapng")
        elif choice == '0':
            break
        else:
            print("Invalid option. Try again.")


if __name__ == "__main__":
    main_menu()
