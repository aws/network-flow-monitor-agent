// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use hashbrown::HashMap;
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};

pub trait CommandRunner {
    fn run(&mut self, cmd: &str, args: &[&str]) -> std::io::Result<Output>;
}

#[derive(Default)]
pub struct RealCommandRunner;

impl CommandRunner for RealCommandRunner {
    fn run(&mut self, cmd: &str, args: &[&str]) -> std::io::Result<Output> {
        Command::new(cmd).args(args).output()
    }
}

/* A command runner used for controlled unit tests.
 *
 * Usage:
 *      // Add many command expectations.
 *      let mut fake_runner = FakeCommandRunner::new();
 *      fake_runner.add_expectation("command1", args1, Ok(Output {...}));
 *      fake_runner.add_expectation("command2", args2, Ok(Output {...}));
 *
 *      // Share the command runner with other objects by cloning it.
 *      ... fake_runner.clone() ...
 *
 *      // Do work.
 *
 *      // Confirm all commands were run.
 *      assert!(fake_runner.expectations.lock().unwrap().is_empty());
 *
 */
#[derive(Clone, Default)]
pub struct FakeCommandRunner {
    pub expectations: Arc<Mutex<HashMap<String, std::io::Result<Output>>>>,
}

impl FakeCommandRunner {
    pub fn new() -> Self {
        Self {
            expectations: Default::default(),
        }
    }

    pub fn add_expectation(&mut self, cmd: &str, args: &[&str], result: std::io::Result<Output>) {
        self.expectations
            .lock()
            .unwrap()
            .insert(Self::full_command(cmd, args), result);
    }

    fn full_command(cmd: &str, args: &[&str]) -> String {
        let mut parts = vec![cmd];
        parts.extend_from_slice(args);
        parts.join(" ")
    }
}

impl CommandRunner for FakeCommandRunner {
    fn run(&mut self, cmd: &str, args: &[&str]) -> std::io::Result<Output> {
        let full_cmd = Self::full_command(cmd, args);
        self.expectations.lock().unwrap().remove(&full_cmd).unwrap()
    }
}
