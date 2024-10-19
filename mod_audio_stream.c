/*
 * mod_audio_stream FreeSWITCH module to stream audio to websocket and receive response
 */
#include <stdbool.h>
#include <math.h>
#include "mod_audio_stream.h"
#include "audio_streamer_glue.h"
#include <switch_json.h>

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_audio_stream_shutdown);
SWITCH_MODULE_RUNTIME_FUNCTION(mod_audio_stream_runtime);
SWITCH_MODULE_LOAD_FUNCTION(mod_audio_stream_load);

SWITCH_MODULE_DEFINITION(mod_audio_stream, mod_audio_stream_load, mod_audio_stream_shutdown, NULL /*mod_audio_stream_runtime*/);

static void responseHandler(switch_core_session_t *session, const char *eventName, const char *json)
{
    switch_event_t *event;
    switch_channel_t *channel = switch_core_session_get_channel(session);
    private_t *tech_pvt = switch_channel_get_private(channel, "audio_stream_pUserData");

    switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, eventName);
    switch_channel_event_set_data(channel, event);
    if (json)
        switch_event_add_body(event, "%s", json);
    switch_event_fire(&event);

    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "responseHandler: starting\n");

    const char *session_uuid = switch_core_session_get_uuid(session);
    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "responseHandler: session UUID: %s\n", session_uuid);

    // Handle audio messages
    if (json && strstr(json, "\"response.audio.delta\"")) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "responseHandler: got delta in response, parsing... \n");
        // Parse the JSON, extract the "delta" field
        cJSON *json_obj = cJSON_Parse(json);
        if (json_obj) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "responseHandler: successfully parsed \n");
            cJSON *delta_obj = cJSON_GetObjectItem(json_obj, "delta");
            if (delta_obj && delta_obj->type == cJSON_String) {
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "responseHandler: delta is a string, decoding\n");
                const char *delta_base64 = delta_obj->valuestring;
                // Decode base64 data
                switch_size_t decoded_len = strlen(delta_base64);
                switch_size_t audio_data_len = (decoded_len * 3) / 4;
                switch_byte_t *audio_data = malloc(audio_data_len);

                if (audio_data) {
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "responseHandler: got audio from string \n");
                    switch_size_t decoded_size = switch_b64_decode(delta_base64, (char *)audio_data, audio_data_len);

                    if (tech_pvt) {
                        // Lock the audio buffer mutex
                        switch_mutex_lock(tech_pvt->audio_buffer_mutex);
                        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "responseHandler: stream session mutex is locked\n");
                        // Write the audio data to the buffer
                        switch_buffer_write(tech_pvt->audio_buffer, audio_data, decoded_size);
                        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "responseHandler: writing audio buffer to stream session...\n");
                        // Unlock the audio buffer mutex
                        switch_mutex_unlock(tech_pvt->audio_buffer_mutex);
                        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "responseHandler: writing finished, stream session mutex is unlocked\n");

                        // Write audio data to file for debugging
                        if (tech_pvt->audio_file && tech_pvt->file_mutex) {
                            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "responseHandler: writing audio to test audio file...\n");
                            switch_mutex_lock(tech_pvt->file_mutex);
                            fwrite(audio_data, 1, decoded_size, tech_pvt->audio_file);
                            fflush(tech_pvt->audio_file);
                            switch_mutex_unlock(tech_pvt->file_mutex);
                        }
                    } else {
                        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "responseHandler: No stream session data\n");
                    }
                    free(audio_data);
                } else {
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "responseHandler: failed to allocate memory for audio data\n");
                }
            }
            cJSON_Delete(json_obj);
        } else {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "responseHandler: failed to parse JSON: %s\n", json);
        }
    }
}

static switch_bool_t capture_callback(switch_media_bug_t *bug, void *user_data, switch_abc_type_t type)
{
    switch_core_session_t *session = switch_core_media_bug_get_session(bug);
    private_t *tech_pvt = (private_t *)user_data;

    switch (type)
    {
    case SWITCH_ABC_TYPE_INIT:
        break;

    case SWITCH_ABC_TYPE_CLOSE:
    {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "capture_callback: SWITCH_ABC_TYPE_CLOSE.\n");
        if (tech_pvt) {
            // Destroy the buffer and mutex
            if (tech_pvt->audio_buffer) {
                switch_buffer_destroy(&tech_pvt->audio_buffer);
            }
            if (tech_pvt->audio_buffer_mutex) {
                switch_mutex_destroy(tech_pvt->audio_buffer_mutex);
            }

            // Close the audio file
            if (tech_pvt->audio_file) {
                fclose(tech_pvt->audio_file);
                tech_pvt->audio_file = NULL;
            }
            if (tech_pvt->file_mutex) {
                switch_mutex_destroy(tech_pvt->file_mutex);
                tech_pvt->file_mutex = NULL;
            }

            // Destroy the timer
            switch_core_timer_destroy(&tech_pvt->timer);

            // Destroy the codec
            if (switch_core_codec_ready(&tech_pvt->codec)) {
                switch_core_codec_destroy(&tech_pvt->codec);
            }

            // Release session reference count
            switch_core_session_rwunlock(session);
        } else {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "capture_callback: tech_pvt is NULL during cleanup\n");
        }
        stream_session_cleanup(session, NULL, 1);
        break;
    }

    case SWITCH_ABC_TYPE_READ:
        return stream_frame(bug);
        break;

    case SWITCH_ABC_TYPE_WRITE_REPLACE:
    {
        switch_frame_t *frame = switch_core_media_bug_get_write_replace_frame(bug);
        switch_byte_t *data = frame->data;
        uint32_t data_len = frame->datalen;
        uint32_t bytes_needed = data_len;

        if (tech_pvt) {
            // Read data from the audio buffer
            switch_mutex_lock(tech_pvt->audio_buffer_mutex);
            uint32_t bytes_available = (uint32_t)switch_buffer_inuse(tech_pvt->audio_buffer);
            if (bytes_available >= bytes_needed) {
                switch_buffer_read(tech_pvt->audio_buffer, data, bytes_needed);
                frame->samples = bytes_needed / 2; // Assuming 16-bit samples
            } else if (bytes_available > 0) {
                // Not enough data, read what we have and fill the rest with silence
                uint32_t bytes_to_read = bytes_available;
                switch_buffer_read(tech_pvt->audio_buffer, data, bytes_to_read);
                memset(data + bytes_to_read, 0, data_len - bytes_to_read);
                frame->samples = data_len / 2;
            } else {
                // No data, fill with silence
                memset(data, 0, data_len);
                frame->samples = data_len / 2;
            }
            switch_mutex_unlock(tech_pvt->audio_buffer_mutex);

            return SWITCH_TRUE; // Indicate that we have replaced the frame
        }
        break;
    }

    case SWITCH_ABC_TYPE_READ_REPLACE:
    {
        switch_channel_t *channel = switch_core_session_get_channel(session);
        switch_frame_t *frame = switch_core_media_bug_get_read_replace_frame(bug);

        uint32_t bytes_needed = frame->datalen;

        frame->codec = &tech_pvt->codec;
        frame->samples = bytes_needed / 2; // Assuming 16-bit samples

        if (switch_channel_ready(channel)) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "CHANNEL IS READY!!\n");
            if (switch_core_session_write_frame(session, frame, SWITCH_IO_FLAG_NONE, 0) != SWITCH_STATUS_SUCCESS) {
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "FAILED TO WRITE FRAME!\n");
            }
        } else {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "CHANNEL IS NOT READY!!\n");
        }
        break;
    }

    default:
        break;
    }

    return SWITCH_TRUE;
}

static switch_status_t start_capture(switch_core_session_t *session,
                                     switch_media_bug_flag_t flags,
                                     char *address,
                                     int sampling,
                                     char *metadata)
{
    switch_channel_t *channel = switch_core_session_get_channel(session);
    switch_media_bug_t *bug;
    switch_status_t status;
    switch_codec_t *read_codec;

    void *pUserData = NULL;
    int channels = (flags & SMBF_STEREO) ? 2 : 1;

    if (switch_channel_get_private(channel, MY_BUG_NAME))
    {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "mod_audio_stream: bug already attached!\n");
        return SWITCH_STATUS_FALSE;
    }

    read_codec = switch_core_session_get_read_codec(session);

    if (switch_channel_pre_answer(channel) != SWITCH_STATUS_SUCCESS)
    {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "mod_audio_stream: channel must have reached pre-answer status before calling start!\n");
        return SWITCH_STATUS_FALSE;
    }

    // Ensure FreeSWITCH remains in the media path
    switch_channel_set_variable(channel, "bypass_media", "false");
    switch_channel_set_variable(channel, "proxy_media", "false");

    char wsUri[MAX_WS_URI];
    char tcpAddress[MAX_WS_URI];

    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "starting validate_address\n");
    int port = return_port(address);
    bool isWs = validate_address(address, wsUri, tcpAddress, 0);

    const char *session_uuid = switch_core_session_get_uuid(session);
    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "start_capture: session UUID: %s\n", session_uuid);

    // pUserData is already initialized to NULL

    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "start_capture: Before stream_session_init, pUserData = %p\n", pUserData);

    if (isWs)
    {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "calling stream_session_init for WS.\n");
        if (SWITCH_STATUS_FALSE == stream_session_init(session, responseHandler, read_codec->implementation->actual_samples_per_second,
                                                       wsUri, 0, sampling, channels, metadata, &pUserData))
        {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Error initializing mod_audio_stream WS session.\n");
            return SWITCH_STATUS_FALSE;
        }
    }
    else
    {
        address[strlen(address) - ((int)log10(port) + 2)] = '\0';
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "calling stream_session_init for TCP.\n");
        if (SWITCH_STATUS_FALSE == stream_session_init(session, responseHandler, read_codec->implementation->actual_samples_per_second,
                                                       address, port, sampling, channels, metadata, &pUserData))
        {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Error initializing mod_audio_stream TCP session.\n");
            return SWITCH_STATUS_FALSE;
        }
    }

    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "start_capture: After stream_session_init, pUserData = %p\n", pUserData);

    private_t *tech_pvt = (private_t *)pUserData;

    // Initialize the codec
    switch_codec_t *codec = &tech_pvt->codec;
    switch_status_t codec_status = switch_core_codec_init(codec, "L16", NULL, NULL, sampling, 20, 1,
                                                          SWITCH_CODEC_FLAG_ENCODE | SWITCH_CODEC_FLAG_DECODE, NULL, switch_core_session_get_pool(session));
    if (codec_status != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Failed to initialize codec\n");
        return SWITCH_STATUS_FALSE;
    }

    // Set the read and write codecs on the session
    switch_core_session_set_read_codec(session, codec);
    switch_core_session_set_write_codec(session, codec);

    // Initialize audio_buffer and audio_buffer_mutex
    switch_buffer_create_dynamic(&tech_pvt->audio_buffer, 1024, 1024 * 1024, 1024 * 1024);
    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "start_capture: audio_buffer initialized\n");

    switch_mutex_init(&tech_pvt->audio_buffer_mutex, SWITCH_MUTEX_NESTED, switch_core_session_get_pool(session));
    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "start_capture: audio_buffer_mutex initialized at %p\n", (void *)tech_pvt->audio_buffer_mutex);

    // Open the audio file
    tech_pvt->audio_file = fopen("/tmp/openai_audio.raw", "wb");
    if (!tech_pvt->audio_file) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Failed to open audio file for writing\n");
    }

    // Initialize file mutex
    switch_mutex_init(&tech_pvt->file_mutex, SWITCH_MUTEX_NESTED, switch_core_session_get_pool(session));

    // Initialize timer for frame timestamps
    switch_core_timer_init(&tech_pvt->timer, "soft", sampling, read_codec->implementation->samples_per_packet, switch_core_session_get_pool(session));

    // Increment session reference count
    switch_core_session_read_lock(session);

    // Store tech_pvt in the channel's private data for access in responseHandler
    switch_channel_set_private(channel, "audio_stream_pUserData", tech_pvt);

    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "adding bug.\n");
    if ((status = switch_core_media_bug_add(session, MY_BUG_NAME, NULL, capture_callback, pUserData, 0, flags, &bug)) != SWITCH_STATUS_SUCCESS)
    {
        return status;
    }
    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "setting bug private data.\n");
    switch_channel_set_private(channel, MY_BUG_NAME, bug);

    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "exiting start_capture.\n");
    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t do_stop(switch_core_session_t *session, char *text)
{
    switch_status_t status = SWITCH_STATUS_SUCCESS;

    if (text)
    {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "mod_audio_stream: stop w/ final text %s\n", text);
    }
    else
    {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "mod_audio_stream: stop\n");
    }
    status = stream_session_cleanup(session, text, 0);

    return status;
}

static switch_status_t do_pauseresume(switch_core_session_t *session, int pause)
{
    switch_status_t status = SWITCH_STATUS_SUCCESS;

    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "mod_audio_stream: %s\n", pause ? "pause" : "resume");
    status = stream_session_pauseresume(session, pause);

    return status;
}

static switch_status_t send_text(switch_core_session_t *session, char *text)
{
    switch_status_t status = SWITCH_STATUS_FALSE;
    switch_channel_t *channel = switch_core_session_get_channel(session);
    switch_media_bug_t *bug = switch_channel_get_private(channel, MY_BUG_NAME);

    if (bug)
    {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "mod_audio_stream: sending text: %s.\n", text);
        status = stream_session_send_text(session, text);
    }
    else
    {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "mod_audio_stream: no bug, failed sending text: %s.\n", text);
    }
    return status;
}

#define STREAM_API_SYNTAX "<uuid> [start | stop | send_text | pause | resume | graceful-shutdown ] [wss-url | path] [mono | mixed | stereo] [8000 | 16000] [metadata]"
SWITCH_STANDARD_API(stream_function)
{
    char *mycmd = NULL, *argv[6] = {0};
    int argc = 0;

    switch_status_t status = SWITCH_STATUS_FALSE;

    if (!zstr(cmd) && (mycmd = strdup(cmd)))
    {
        argc = switch_separate_string(mycmd, ' ', argv, (sizeof(argv) / sizeof(argv[0])));
    }
    assert(cmd);
    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "mod_audio_stream cmd: %s\n", cmd ? cmd : "");

    if (zstr(cmd) || argc < 2 || (0 == strcmp(argv[1], "start") && argc < 4))
    {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Error with command %s %s %s.\n", cmd, argv[0], argv[1]);
        stream->write_function(stream, "-USAGE: %s\n", STREAM_API_SYNTAX);
        goto done;
    }
    else
    {
        switch_core_session_t *lsession = NULL;
        if ((lsession = switch_core_session_locate(argv[0])))
        {
            if (!strcasecmp(argv[1], "stop"))
            {
                if (argc > 2 && (is_valid_utf8(argv[2]) != SWITCH_STATUS_SUCCESS))
                {
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
                                      "%s contains invalid utf8 characters\n", argv[2]);
                    switch_core_session_rwunlock(lsession);
                    goto done;
                }
                status = do_stop(lsession, argc > 2 ? argv[2] : NULL);
            }
            else if (!strcasecmp(argv[1], "pause"))
            {
                status = do_pauseresume(lsession, 1);
            }
            else if (!strcasecmp(argv[1], "resume"))
            {
                status = do_pauseresume(lsession, 0);
            }
            else if (!strcasecmp(argv[1], "send_text"))
            {
                if (argc < 3)
                {
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
                                      "send_text requires an argument specifying text to send\n");
                    switch_core_session_rwunlock(lsession);
                    goto done;
                }
                if (is_valid_utf8(argv[2]) != SWITCH_STATUS_SUCCESS)
                {
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
                                      "%s contains invalid utf8 characters\n", argv[2]);
                    switch_core_session_rwunlock(lsession);
                    goto done;
                }
                status = send_text(lsession, argv[2]);
            }
            else if (!strcasecmp(argv[1], "start"))
            {
                // switch_channel_t *channel = switch_core_session_get_channel(lsession);
                char address[MAX_WS_URI];
                int sampling = 8000;
                switch_media_bug_flag_t flags = SMBF_READ_STREAM;
                char *metadata = argc > 5 ? argv[5] : NULL;
                if (metadata && (is_valid_utf8(metadata) != SWITCH_STATUS_SUCCESS))
                {
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
                                      "%s contains invalid utf8 characters\n", metadata);
                    switch_core_session_rwunlock(lsession);
                    goto done;
                }
                if (0 == strcmp(argv[3], "mixed"))
                {
                    flags |= SMBF_WRITE_STREAM;
                }
                else if (0 == strcmp(argv[3], "stereo"))
                {
                    flags |= SMBF_WRITE_STREAM;
                    flags |= SMBF_STEREO;
                }
                else if (0 == strcmp(argv[3], "mono"))
                {
                    flags |= SMBF_READ_REPLACE; // Use READ_REPLACE instead
                }
                else
                {
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
                                      "invalid mix type: %s, must be mono, mixed, or stereo\n", argv[3]);
                    switch_core_session_rwunlock(lsession);
                    goto done;
                }
                if (0 == strcmp(argv[4], "16k"))
                {
                    sampling = 16000;
                }
                else if (0 == strcmp(argv[4], "8k"))
                {
                    sampling = 8000;
                }
                else
                {
                    sampling = atoi(argv[4]);
                }
                if (strcmp(STREAM_TYPE, "WS") == 0 && !validate_address(argv[2], address, address, 0))
                {
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "invalid address: %s\n", argv[2]);
                }
                else if (sampling % 8000 != 0)
                {
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "invalid sample rate: %s\n", argv[4]);
                }
                else
                {
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "starting start_capture\n");
                    status = start_capture(lsession, flags, argv[2], sampling, metadata);
                }
            }
            else
            {
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
                                  "unsupported mod_audio_stream cmd: %s\n", argv[1]);
            }
            switch_core_session_rwunlock(lsession);
        }
        else
        {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Error locating session %s\n",
                              argv[0]);
        }
    }

    if (status == SWITCH_STATUS_SUCCESS)
    {
        stream->write_function(stream, "+OK Success\n");
    }
    else
    {
        stream->write_function(stream, "-ERR Operation Failed\n");
    }

done:
    switch_safe_free(mycmd);
    return SWITCH_STATUS_SUCCESS;
}

SWITCH_MODULE_LOAD_FUNCTION(mod_audio_stream_load)
{
    switch_api_interface_t *api_interface;

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "mod_audio_stream API loading..\n");

    /* connect my internal structure to the blank pointer passed to me */
    *module_interface = switch_loadable_module_create_module_interface(pool, modname);

    /* create/register custom event message types */
    if (switch_event_reserve_subclass(EVENT_JSON) != SWITCH_STATUS_SUCCESS ||
        switch_event_reserve_subclass(EVENT_CONNECT) != SWITCH_STATUS_SUCCESS ||
        switch_event_reserve_subclass(EVENT_ERROR) != SWITCH_STATUS_SUCCESS ||
        switch_event_reserve_subclass(EVENT_DISCONNECT) != SWITCH_STATUS_SUCCESS)
    {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Couldn't register an event subclass for mod_audio_stream API.\n");
        return SWITCH_STATUS_TERM;
    }
    SWITCH_ADD_API(api_interface, "uuid_audio_stream", "audio_stream API", stream_function, STREAM_API_SYNTAX);
    switch_console_set_complete("add uuid_audio_stream start wss-url metadata");
    switch_console_set_complete("add uuid_audio_stream start wss-url");
    switch_console_set_complete("add uuid_audio_stream stop");

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "mod_audio_stream API successfully loaded\n");

    /* indicate that the module should continue to be loaded */
    return SWITCH_STATUS_SUCCESS;
}

/*
  Called when the system shuts down
  Macro expands to: switch_status_t mod_audio_stream_shutdown() */
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_audio_stream_shutdown)
{
    switch_event_free_subclass(EVENT_JSON);
    switch_event_free_subclass(EVENT_CONNECT);
    switch_event_free_subclass(EVENT_DISCONNECT);
    switch_event_free_subclass(EVENT_ERROR);

    return SWITCH_STATUS_SUCCESS;
}
