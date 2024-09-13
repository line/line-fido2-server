/*
 * Copyright 2024 LY Corporation
 *
 * LY Corporation licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package com.linecorp.line.auth.fido.fido2.common.server.bean.validation;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeAll;

import javax.validation.Validation;
import javax.validation.Validator;
import java.util.Locale;

public class BeanValidationTestSupport {

    protected static final String MUST_NOT_BE_NULL = "must not be null";
    protected static final String MUST_NOT_BE_BLANK = "must not be blank";
    protected static final String MUST_BE_A_WELL_FORMED_BASE_64 = "must be a well-formed base64";
    protected static final String LENGTH_MUST_BE_BETWEEN_1_AND_64 = "length must be between 1 and 64";
    protected static final String NOT_VALID_BASE64_URL_STRING = "!@=/+";

    protected static final ObjectMapper objectMapper = new ObjectMapper();
    protected static Validator validator;

    @BeforeAll
    static void init() {
        Locale.setDefault(Locale.ENGLISH);
        validator = Validation.buildDefaultValidatorFactory().getValidator();
    }
}
