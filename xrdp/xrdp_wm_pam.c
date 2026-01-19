/**
 * xrdp: A Remote Desktop Protocol server.
 *
 * Copyright (C) Jay Sorg 2004-2024, all xrdp contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * PAM conversation UI functions for interactive authentication
 */

#if defined(HAVE_CONFIG_H)
#include <config_ac.h>
#endif

#include "xrdp.h"
#include "log.h"
#include "string_calls.h"

/*****************************************************************************/
/**
 * Sanitize PAM message for safe display
 * Removes control characters and limits length
 *
 * @param msg Message to sanitize
 * @param max_length Maximum length for output
 * @return Sanitized message (caller must free)
 */
static char *
sanitize_pam_message(const char *msg, size_t max_length)
{
    if (msg == NULL)
    {
        return g_strdup("");
    }

    size_t msg_len = g_strlen(msg);
    if (msg_len > max_length)
    {
        msg_len = max_length;
    }

    char *sanitized = (char *)g_malloc(msg_len + 4, 1);  /* +4 for "...\0" */
    size_t j = 0;

    for (size_t i = 0; i < msg_len && j < max_length; i++)
    {
        char c = msg[i];

        /* Allow printable chars, newline, and tab */
        if ((c >= 32 && c <= 126) || c == '\n' || c == '\t')
        {
            sanitized[j++] = c;
        }
        else
        {
            /* Replace control chars with space */
            sanitized[j++] = ' ';
        }
    }

    /* Add ellipsis if truncated */
    if (g_strlen(msg) > max_length)
    {
        sanitized[j++] = '.';
        sanitized[j++] = '.';
        sanitized[j++] = '.';
    }

    sanitized[j] = '\0';
    return sanitized;
}

/*****************************************************************************/
/**
 * Display a PAM prompt to the user
 *
 * @param self Window manager
 * @param message Message to display
 * @param echo_on 1 for visible input, 0 for masked
 * @return 0 on success
 */
int
xrdp_wm_show_pam_prompt(struct xrdp_wm *self,
                        const char *message,
                        int echo_on)
{
    char *sanitized_msg;
    size_t current_len;
    size_t new_msg_len;
    size_t available_space;

    if (self == NULL || message == NULL)
    {
        return 1;
    }

    LOG(LOG_LEVEL_DEBUG, "PAM prompt: echo_on=%d, msg='%s'", echo_on, message);

    /* Sanitize the message */
    sanitized_msg = sanitize_pam_message(message, 512);

    /* Append message to accumulated messages */
    current_len = g_strlen(self->pam_accumulated_messages);
    new_msg_len = g_strlen(sanitized_msg);
    available_space = sizeof(self->pam_accumulated_messages) - current_len - 1;

    if (new_msg_len < available_space)
    {
        g_strncat(self->pam_accumulated_messages, sanitized_msg, available_space);
        g_strncat(self->pam_accumulated_messages, "\n",
                  sizeof(self->pam_accumulated_messages) - g_strlen(self->pam_accumulated_messages) - 1);
    }

    /* Update message display area if it exists */
    if (self->pam_message_box != NULL)
    {
        set_string(&self->pam_message_box->caption1, self->pam_accumulated_messages);
        xrdp_bitmap_invalidate(self->pam_message_box, NULL);
    }

    /* Update input label if it exists */
    if (self->pam_input_label != NULL)
    {
        set_string(&self->pam_input_label->caption1, sanitized_msg);
        xrdp_bitmap_invalidate(self->pam_input_label, NULL);
    }

    /* Show/configure input field based on prompt type */
    if (self->pam_input_field != NULL)
    {
        self->pam_input_echo_on = echo_on;

        /* Set password mode ('*' for masked, 0 for visible) */
        self->pam_input_field->password_char = (echo_on == 0) ? '*' : 0;

        /* Clear the input field */
        set_string(&self->pam_input_field->caption1, "");

        /* Make visible */
        self->pam_input_field->state = 0;  /* visible */
        xrdp_bitmap_invalidate(self->pam_input_field, NULL);

        /* Set focus to input field */
        xrdp_wm_set_focused(self, self->pam_input_field);
    }

    /* Show submit button */
    if (self->pam_submit_button != NULL)
    {
        self->pam_submit_button->state = 0;  /* visible */
        xrdp_bitmap_invalidate(self->pam_submit_button, NULL);
    }

    /* Set PAM submit button as default for Enter key */
    if (self->login_window != NULL && self->pam_submit_button != NULL)
    {
        self->login_window->default_button = self->pam_submit_button;
    }

    /* Mark PAM conversation as active */
    self->pam_conversation_active = 1;

    g_free(sanitized_msg);
    return 0;
}

/*****************************************************************************/
/**
 * Display PAM info/error message (no input needed)
 *
 * @param self Window manager
 * @param message Message to display
 * @return 0 on success
 */
int
xrdp_wm_show_pam_info(struct xrdp_wm *self, const char *message)
{
    char *sanitized_msg;
    size_t current_len;
    size_t new_msg_len;
    size_t available_space;

    if (self == NULL || message == NULL)
    {
        return 1;
    }

    LOG(LOG_LEVEL_DEBUG, "PAM info: msg='%s'", message);

    /* Sanitize the message */
    sanitized_msg = sanitize_pam_message(message, 512);

    /* Append message to accumulated messages */
    current_len = g_strlen(self->pam_accumulated_messages);
    new_msg_len = g_strlen(sanitized_msg);
    available_space = sizeof(self->pam_accumulated_messages) - current_len - 1;

    if (new_msg_len < available_space)
    {
        g_strncat(self->pam_accumulated_messages, sanitized_msg, available_space);
        g_strncat(self->pam_accumulated_messages, "\n",
                  sizeof(self->pam_accumulated_messages) - g_strlen(self->pam_accumulated_messages) - 1);
    }

    /* Update message display area if it exists */
    if (self->pam_message_box != NULL)
    {
        set_string(&self->pam_message_box->caption1, self->pam_accumulated_messages);
        xrdp_bitmap_invalidate(self->pam_message_box, NULL);
    }

    /* Update label if it exists */
    if (self->pam_input_label != NULL)
    {
        set_string(&self->pam_input_label->caption1, sanitized_msg);
        xrdp_bitmap_invalidate(self->pam_input_label, NULL);
    }

    /* Hide input field (no response needed for info messages) */
    if (self->pam_input_field != NULL)
    {
        self->pam_input_field->state = 1;  /* hidden */
        xrdp_bitmap_invalidate(self->pam_input_field, NULL);
    }

    /* Hide submit button */
    if (self->pam_submit_button != NULL)
    {
        self->pam_submit_button->state = 1;  /* hidden */
        xrdp_bitmap_invalidate(self->pam_submit_button, NULL);
    }

    g_free(sanitized_msg);
    return 0;
}

/*****************************************************************************/
/**
 * Handle submit button click during PAM conversation
 *
 * @param self Window manager
 * @return 0 on success
 */
int
xrdp_wm_pam_submit_clicked(struct xrdp_wm *self)
{
    char response[256];

    if (self == NULL || self->mm == NULL)
    {
        return 1;
    }

    LOG(LOG_LEVEL_DEBUG, "PAM submit button clicked");

    /* Get input field text */
    if (self->pam_input_field != NULL && self->pam_input_field->caption1 != NULL)
    {
        g_strncpy(response, self->pam_input_field->caption1, sizeof(response) - 1);
        response[sizeof(response) - 1] = '\0';
    }
    else
    {
        response[0] = '\0';
    }

    /* Send response to sesman via mm */
    if (xrdp_mm_send_pam_response(self->mm, response) != 0)
    {
        LOG(LOG_LEVEL_ERROR, "Failed to send PAM response");
        return 1;
    }

    /* Clear and hide input field */
    if (self->pam_input_field != NULL)
    {
        set_string(&self->pam_input_field->caption1, "");
        self->pam_input_field->state = 1;  /* hidden */
        xrdp_bitmap_invalidate(self->pam_input_field, NULL);
    }

    /* Hide submit button */
    if (self->pam_submit_button != NULL)
    {
        self->pam_submit_button->state = 1;  /* hidden */
        xrdp_bitmap_invalidate(self->pam_submit_button, NULL);
    }

    /* Show waiting indicator */
    xrdp_wm_show_pam_info(self, "Processing...");

    return 0;
}
